
module.exports.MerkleTreeIDMap = {
	"MASTER":           0,
	"KBFS_PUBLIC":      1,
	"KBFS_PRIVATE":     2,
	"KBFS_PRIVATETEAM": 3
};

module.exports.NodeType = {
  None: 0,
  INode: 1,
  Leaf: 2
}
module.exports.PublicTLFCryptKey = new Uint8Array(32).fill(0x18);

module.exports.BlockEncryptionType = {
  EncryptionSecretbox: 1,
  EncryptionSecretboxWithKeyNonce: 2
}
module.exports.DirType = {
  File: 0,
  Exec: 1,
  Dir: 2,
  Sym: 3
}
