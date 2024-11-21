import 'dart:typed_data';

const int OUT_LEN = 32;
const int KEY_LEN = 32;
const int BLOCK_LEN = 64;
const int CHUNK_LEN = 1024;

const int CHUNK_START = 1 << 0;
const int CHUNK_END = 1 << 1;
const int PARENT = 1 << 2;
const int ROOT = 1 << 3;
const int KEYED_HASH = 1 << 4;
const int DERIVE_KEY_CONTEXT = 1 << 5;
const int DERIVE_KEY_MATERIAL = 1 << 6;

const List<int> IV = [
  0x6A09E667,
  0xBB67AE85,
  0x3C6EF372,
  0xA54FF53A,
  0x510E527F,
  0x9B05688C,
  0x1F83D9AB,
  0x5BE0CD19,
];

const List<int> MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

int mask32(int x) => x & 0xFFFFFFFF;

int add32(int x, int y) => mask32(x + y);

int rightRotate32(int x, int n) => mask32((x >> n) | (x << (32 - n)));

void g(List<int> state, int a, int b, int c, int d, int mx, int my) {
  state[a] = add32(state[a], add32(state[b], mx));
  state[d] = rightRotate32(state[d] ^ state[a], 16);
  state[c] = add32(state[c], state[d]);
  state[b] = rightRotate32(state[b] ^ state[c], 12);
  state[a] = add32(state[a], add32(state[b], my));
  state[d] = rightRotate32(state[d] ^ state[a], 8);
  state[c] = add32(state[c], state[d]);
  state[b] = rightRotate32(state[b] ^ state[c], 7);
}

void roundFunc(List<int> state, List<int> m) {
  // 混合列
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  // 混合对角线
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

void permute(List<int> m) {
  var original = List<int>.from(m);
  for (int i = 0; i < 16; i++) {
    m[i] = original[MSG_PERMUTATION[i]];
  }
}

List<int> compress(
    List<int> chainingValue, List<int> blockWords, int counter, int blockLen, int flags) {
  var state = [
    chainingValue[0],
    chainingValue[1],
    chainingValue[2],
    chainingValue[3],
    chainingValue[4],
    chainingValue[5],
    chainingValue[6],
    chainingValue[7],
    IV[0],
    IV[1],
    IV[2],
    IV[3],
    mask32(counter),
    mask32(counter >> 32),
    blockLen,
    flags,
  ];

  assert(blockWords.length == 16);
  var block = List<int>.from(blockWords);

  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);
  permute(block);
  roundFunc(state, block);

  for (int i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= chainingValue[i];
  }

  return state;
}

// 确保密钥长度为 32 字节
List<int> wordsFromLittleEndianBytesNewkey(Uint8List b) {
  final key = Uint8List(32);
  final keyLength = b.length;
  for (int i = 0; i < 32; i++) {
    key[i] = i < keyLength ? b[i] : 0;
  }

  List<int> words = [];
  var byteData = key.buffer.asByteData();
  for (int i = 0; i < key.length; i += 4) {
    words.add(byteData.getUint32(i, Endian.little));
  }
  return words;
}

List<int> wordsFromLittleEndianBytes(Uint8List b) {
  assert(b.length % 4 == 0);
  List<int> words = [];
  var byteData = b.buffer.asByteData();
  for (int i = 0; i < b.length; i += 4) {
    words.add(byteData.getUint32(i, Endian.little));
  }
  return words;
}

class Output {
  List<int> inputChainingValue;
  List<int> blockWords;
  int counter;
  int blockLen;
  int flags;

  Output(
      this.inputChainingValue, this.blockWords, this.counter, this.blockLen, this.flags);

  List<int> chainingValue() {
    return compress(inputChainingValue, blockWords, counter, blockLen, flags).sublist(0, 8);
  }

  Uint8List rootOutputBytes(int length) {
    var outputBytes = BytesBuilder();
    int i = 0;
    while (i < length) {
      var words = compress(
          inputChainingValue, blockWords, i ~/ 64, blockLen, flags | ROOT);
      for (var word in words) {
        var wordBytes = Uint8List(4);
        wordBytes.buffer.asByteData().setUint32(0, word, Endian.little);
        int take = (length - i).clamp(0, wordBytes.length);
        outputBytes.add(wordBytes.sublist(0, take));
        i += take;
        if (i >= length) {
          break;
        }
      }
    }
    return outputBytes.toBytes();
  }
}

class ChunkState {
  List<int> chainingValue;
  int chunkCounter;
  Uint8List block;
  int blockLen;
  int blocksCompressed;
  int flags;

  ChunkState(this.chainingValue, this.chunkCounter, this.flags)
      : block = Uint8List(BLOCK_LEN),
        blockLen = 0,
        blocksCompressed = 0;

  int len() => BLOCK_LEN * blocksCompressed + blockLen;

  int startFlag() => blocksCompressed == 0 ? CHUNK_START : 0;

  void update(Uint8List inputBytes) {
    int inputIndex = 0;
    while (inputIndex < inputBytes.length) {
      if (blockLen == BLOCK_LEN) {
        var blockWords = wordsFromLittleEndianBytes(block);
        chainingValue = compress(
                chainingValue, blockWords, chunkCounter, BLOCK_LEN, flags | startFlag())
            .sublist(0, 8);
        blocksCompressed += 1;
        block = Uint8List(BLOCK_LEN);
        blockLen = 0;
      }
      int want = BLOCK_LEN - blockLen;
      int take = (inputBytes.length - inputIndex).clamp(0, want);
      block.setRange(blockLen, blockLen + take, inputBytes, inputIndex);
      blockLen += take;
      inputIndex += take;
    }
  }

  Output output() {
    var blockWords = wordsFromLittleEndianBytes(block);
    return Output(
        chainingValue,
        blockWords,
        chunkCounter,
        blockLen,
        flags | startFlag() | CHUNK_END);
  }
}

Output parentOutput(
    List<int> leftChildCv, List<int> rightChildCv, List<int> keyWords, int flags) {
  return Output(keyWords, leftChildCv + rightChildCv, 0, BLOCK_LEN, PARENT | flags);
}

List<int> parentCv(
    List<int> leftChildCv, List<int> rightChildCv, List<int> keyWords, int flags) {
  return parentOutput(leftChildCv, rightChildCv, keyWords, flags).chainingValue();
}

class Hasher {
  ChunkState chunkState;
  List<int> keyWords;
  List<List<int>> cvStack;
  int flags;

  Hasher(this.keyWords, this.flags):cvStack=[],chunkState=ChunkState(keyWords, 0, flags){
    assert(keyWords.length == 8);
  }

  Hasher.newDefault() : this(IV, 0);

  Hasher.newKeyed(Uint8List key)
      : this(wordsFromLittleEndianBytesNewkey(key), KEYED_HASH);

  Hasher.newDeriveKey(String context)
      : keyWords = [],
        flags = 0,
        chunkState = ChunkState([], 0, 0),
        cvStack = [] {
    var contextHasher = Hasher(IV, DERIVE_KEY_CONTEXT);
    contextHasher.update(Uint8List.fromList(context.codeUnits));
    var contextKey = contextHasher.finalize(KEY_LEN);
    var contextKeyWords = wordsFromLittleEndianBytes(contextKey);
    keyWords = contextKeyWords;
    flags = DERIVE_KEY_MATERIAL;
    chunkState = ChunkState(keyWords, 0, flags);
    cvStack = [];
  }

  void addChunkChainingValue(List<int> newCv, int totalChunks) {
    while (totalChunks & 1 == 0) {
      newCv = parentCv(cvStack.removeLast(), newCv, keyWords, flags);
      totalChunks >>= 1;
    }
    cvStack.add(newCv);
  }

  void update(Uint8List inputBytes) {
    int inputIndex = 0;
    while (inputIndex < inputBytes.length) {
      if (chunkState.len() == CHUNK_LEN) {
        var chunkCv = chunkState.output().chainingValue();
        int totalChunks = chunkState.chunkCounter + 1;
        addChunkChainingValue(chunkCv, totalChunks);
        chunkState = ChunkState(keyWords, totalChunks, flags);
      }
      int want = CHUNK_LEN - chunkState.len();
      int take = (inputBytes.length - inputIndex).clamp(0, want);
      chunkState.update(inputBytes.sublist(inputIndex, inputIndex + take));
      inputIndex += take;
    }
  }

  Uint8List finalize([int length = OUT_LEN]) {
    Output output = chunkState.output();
    int parentNodesRemaining = cvStack.length;
    while (parentNodesRemaining > 0) {
      parentNodesRemaining -= 1;
      output = parentOutput(
          cvStack[parentNodesRemaining], output.chainingValue(), keyWords, flags);
    }
    return output.rootOutputBytes(length);
  }
}

// 新增的 BLAKE3 哈希计算方法
Uint8List blake3WithKey(Uint8List input, Uint8List key32) {
  Hasher keyedHasher = Hasher.newKeyed(key32);

  keyedHasher.update(input);
  Uint8List keyedHash = keyedHasher.finalize();

  return keyedHash;
}
// 新增的 BLAKE3 哈希计算方法 默认密钥
Uint8List blake3WithDefaultKey(Uint8List input) {
  Hasher keyedHasher = Hasher.newDefault();

  keyedHasher.update(input);
  Uint8List keyedHash = keyedHasher.finalize();

  return keyedHash;
}