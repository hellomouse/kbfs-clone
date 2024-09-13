const rpc = require('framed-msgpack-rpc');
const purepack = require("purepack");
const nacl = require("tweetnacl");
const constants = require("./constants"); 
const util = require("util");
const fs = require("fs");
const crypto = require("crypto");
const inspect = util.inspect;

class KBFSClient {
  constructor() {
    this.MDServer = rpc.createTransport({
      host: 'mdserver-0.kbfs.keybase.io',
      port : 443,
      tls_opts: { rejectUnauthorized: false },
      robust: true
    });
    this.BServer = rpc.createTransport({
      host: 'bserver-0.kbfs.keybase.io',
      port : 443,
      tls_opts: { rejectUnauthorized: false },
      robust: true
    });
  }
  async connectMD() {
    this.MDClient = new rpc.Client(this.MDServer, "keybase.1.metadata");
    await util.promisify(this.MDServer.connect).bind(this.MDServer)();
  }
  async connectB() {
    this.BClient = new rpc.Client(this.BServer, "keybase.1.block");
    await util.promisify(this.BServer.connect).bind(this.BServer)();
  }
  close() {
    this.MDServer.close()
    this.BServer.close()
  }
  async mdCall(method, args) {
    if (!this.MDClient) await this.connectMD();
    const MDClientCall = util.promisify(this.MDClient.invoke).bind(this.MDClient);
    return MDClientCall(method, [args]);
  }
  async bCall(method, args) {
    if (!this.BClient) await this.connectB();
    const BClientCall = util.promisify(this.BClient.invoke).bind(this.BClient);
    return BClientCall(method, [args]);
  }
  // tree encoding: https://github.com/keybase/go-merkle-tree/blob/master/types.go
  async getRoot() {
    const resp = await this.mdCall("getMerkleRootLatest", {
      treeID: constants.MerkleTreeIDMap.KBFS_PUBLIC
    });
    const root = purepack.unpack(resp.root);
    return {
      hash: root.h.toString("hex"),
      prev: root.pr.toString("hex"),
      seqno: root.sn,
      timestamp: root.ts
    }
  }
  async getNode(hash) {
    const resp = await this.mdCall("getMerkleNode", {
      hash
    });
    return purepack.unpack(resp);
  }
  async getFolder(folderID) {
    return await this.mdCall("getMetadataByTimestamp", {
      folderID,
      serverTime: Date.now()
    });
  }
  async getBlock(blockID, type, folderID, creator) {
    return await this.bCall("getBlock", {
      bid: {
        blockHash: blockID,
        chargedTo: creator,
        blockType: type
      },
      folder: folderID,
      sizeOnly: false
    });
  }
}

class KBFSDownloader {
  constructor() {
    this.kbfs = new KBFSClient();
    this.storageFolder = "kbfs";
    this.metaFolder = "kbfsmeta";
    this.diskUsageThreshold = 5_000_000_000;
    this.fileSizeThreshold = 300_000_000;
    this.quota = 0;
  }
  close() {
    this.kbfs.close();
  }
  async makeFolders() {
    await fs.promises.mkdir(this.storageFolder).catch(() => null);
    await fs.promises.mkdir(this.metaFolder).catch(() => null);
  }
  async fetchAllMeta(){
    const root = await this.kbfs.getRoot();
    return this.fetchNode(root.hash);
  }
  async fetchNode(hash){
    const node = await this.kbfs.getNode(hash);
    switch (node.t) {
      case constants.NodeType.INode:
        for (let child of node.i) {
          await this.fetchNode(child.toString("hex"))
        }
        break;
      case constants.NodeType.Leaf:
        for (const child of node.l) await this.fetchTopLevelFolderMeta(child[0].toString("hex"))
        break;
      default: throw new Error("unknown node type");
    }
  }
  decryptBlock(encrypted, serverHalf) {
    let key, nonce;
    switch (encrypted.v) {
      case constants.BlockEncryptionType.EncryptionSecretbox: {
        key = serverHalf.map((v, i) => v^constants.PublicTLFCryptKey[i]);
        nonce = encrypted.n
        break;
      }
      case constants.BlockEncryptionType.EncryptionSecretboxWithKeyNonce: {
        const hash = crypto.createHmac("sha512", constants.PublicTLFCryptKey).update(serverHalf).digest();
        key = hash.slice(0, 32);
        nonce = hash.slice(32, 32+24);
        break;
      }
      default: throw new Error("unknown block keying scheme")
    }
    const dec = nacl.secretbox.open(new Uint8Array(encrypted.e), new Uint8Array(nonce), new Uint8Array(key));
    if (!dec) throw new Error("couldn't decrypt");
    return Buffer.from(dec);
  }
  async fetchChunk(blockID, type, folder, creator) {
    const block = await this.kbfs.getBlock(blockID, type, folder, creator);
    const serverHalf = Buffer.from(block.blockKey,"hex");
    const encrypted = purepack.unpack(block.buf);
    const buf = this.decryptBlock(encrypted, serverHalf);
    return purepack.unpack(buf.slice(4));
  }
  async fetchFile(fileName, blockID, type, folder, creator) {
    const fileData = await this.fetchChunk(blockID, type, folder, creator);
    let contents = Buffer.alloc(0);
    if (fileData.c) contents = fileData.c
    if (fileData.i) {
      const chunks = fileData.i;
      for (const chunk of chunks) {
        const chunkBlockID = chunk.i.toString("hex");
        const chunkData = await this.fetchChunk(chunkBlockID, chunk.b || 0, folder, chunk.c);
        if (!chunkData.c) chunkData.c = Buffer.alloc(0);
        contents = Buffer.concat([contents, chunkData.c]);
        if (contents.length > this.fileSizeThreshold) {
          console.log(`??? File ${fileName} contains more data than claimed.`);
          return await fs.promises.writeFile(fileName + ".notdownloaded", "");
        }
      }
    }
    this.quota -= contents.length;
    if (this.quota < 0) {
      console.log(`??? Exceeded quota while downloading ${fileName}. Size is probably wrong`);
    }
    await fs.promises.writeFile(fileName, contents);
  }
  async fetchFolder(pathName, blockID, type, folder, creator) {
    const dirData = await this.fetchChunk(blockID, type, folder, creator);
    if (!dirData.c) return; // empty
    for (const [childName, child] of Object.entries(dirData.c)) {
      const location = pathName + "/" + encodeURIComponent(childName);
      if (child.Type == constants.DirType.Sym) {
        await fs.promises.writeFile(location, `SymLink to ${child.SymPath}`);
        continue;
      }
      const childBlockID = child.i.toString("hex");
      console.log(location);
      if (child.Type == constants.DirType.Dir) {
        await fs.promises.mkdir(location).catch(err => null);
        await this.fetchFolder(location, childBlockID, child.b || 0, folder, child.c).catch(err => console.log(`Error while fetching ${location}: ${inspect(err)}`));
        continue;
      }
      if (child.Size > this.fileSizeThreshold) {
        console.log(`!!! Skipping ${location} because it's size is ${child.Size}`);
        await fs.promises.writeFile(location + ".notdownloaded", "");
        continue;
      };
      if (child.Size > this.quota) {
        console.log(`!!! Skipping ${location} because quota=${this.quota}`);
        await fs.promises.writeFile(location + ".notdownloaded", "");
        continue;
      }
      await this.fetchFile(location, childBlockID, child.b || 0, folder, child.c).catch(err => console.log(`Error while fetching ${location}: ${inspect(err)}`))
    }
  }
  async fetchTopLevelFolderMeta(folder) {
    const [dirData, metaData] = await this.fetchFolderMeta(folder);
    await fs.promises.writeFile(`${this.metaFolder}/${folder}_dir.json`, JSON.stringify(dirData));
    await fs.promises.writeFile(`${this.metaFolder}/${folder}_meta.json`, JSON.stringify(metaData));
    console.log(`Fetched metadata for ${folder}`);
  }
  async fetchTopLevelFolder(folder) {
    const dir = JSON.parse(await fs.promises.readFile(`${this.metaFolder}/${folder}_dir.json`));
    const blockID = Buffer.from(dir.Dir.i).toString("hex");
    const pathName = this.storageFolder + "/" + folder;
    await fs.promises.mkdir(pathName).catch(err => null);
    await this.fetchFolder(pathName, blockID, dir.Dir.b || 0, folder, dir.Dir.c);
  }
  async fetchFolderMeta(folder){
    const resp = await this.kbfs.getFolder(folder);
    if (!resp.block) throw new Error("no valid response about folder");
    const block = purepack.unpack(resp.block);
    const blockData = block.MD?.wmd?.data || block.MD.data;
    if (!blockData) throw new Error("no data about folder!");
    const encrypted = purepack.unpack(blockData, { ext: () => null });
    if (!encrypted.n && encrypted.Dir) {
      return [encrypted, block] // not actually encrypted
    }
    const decrypted = Buffer.from(nacl.secretbox.open(new Uint8Array(encrypted.e), new Uint8Array(encrypted.n), constants.PublicTLFCryptKey));
    const dir = purepack.unpack(decrypted, { ext: () => null });
    return [dir, block];
  }
  async fetchAllElegibleContents(prefix="") { // prefix for splitting the task into chunks
    const metaFiles = await fs.promises.readdir(this.metaFolder);
    const folderIDs = metaFiles.filter(fileName => fileName.endsWith("_meta.json")).map(fileName => fileName.replace("_meta.json", ""));
    for (const folder of folderIDs) {
      if (!folder.startsWith(prefix)) continue;
      const metaData = JSON.parse(await fs.promises.readFile(`${this.metaFolder}/${folder}_meta.json`));
      const dirData = JSON.parse(await fs.promises.readFile(`${this.metaFolder}/${folder}_dir.json`));
      const diskUsage = (metaData.MD.wmd||metaData.MD).DiskUsage;
      if (diskUsage > this.diskUsageThreshold) {
        console.log(`!!! Folder ${folder} with claimed size ${(diskUsage/1e9).toFixed(2)}GB may be incomplete`)
      };
      this.quota = this.diskUsageThreshold; // refill quota
      try {
        await this.fetchTopLevelFolder(folder);
        console.log(`Fetched folder ${folder}`);
      } catch(err) { console.log(`Error while fetching ${folder}: ${inspect(err)}`) }
    }
  }
}

async function main(){
  const kbfsDownloader = new KBFSDownloader();
  await kbfsDownloader.makeFolders();
  const cmd = process.argv[2];
  const argv = process.argv.slice(3);
  if (cmd == "allmeta") {
    await kbfsDownloader.fetchAllMeta();
  }
  if (cmd == "somemeta") {
    await kbfsDownloader.fetchTopLevelFolderMeta(argv[0]);
  }
  if (cmd == "allcontent") {
    await kbfsDownloader.fetchAllElegibleContents(argv[0]);
  }
  if (cmd == "shownames") {
    kbfsDownloader.fileSizeThreshold = -1;
    await kbfsDownloader.fetchTopLevelFolder(argv[0]);
  }
  kbfsDownloader.close();
}

async function _main() {
  try{
    await main()
  } catch(e){console.log(e)}
}
_main();
