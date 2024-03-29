# Cryptopals

This repository has my [cryptopals](https://cryptopals.com/) solutions, which are a set of cryptography-related programming challenges. Each challenge is run as a test, stored under `sets/setN/chalM_test.go` for some set `N` and challenge `M`. The rest of the codes are stored under `pkg` and `internal`.

To run a specific set:

```sh
# N for set number
go test ./sets/setN

# e.g. running set 1 with verbose flag
go test ./sets/set1 -v
```

To run a specific challenge, similarly:

```sh
go test ./sets/setN/chalM_test.go -v
```

## TODO

- Add `internal/testing` utilities that prints expected / received kind of errors.

## Challenges

- [x] [Set 1](./sets/set1/): [Basics](https://cryptopals.com/sets/1)
  - [x] [Challenge 1](./sets/set1/chal1_test.go): [Convert `hex` to `base64`](https://cryptopals.com/sets/1/challenges/1)
  - [x] [Challenge 2](./sets/set1/chal2_test.go): [Fixed XOR](https://cryptopals.com/sets/1/challenges/2)
  - [x] [Challenge 3](./sets/set1/chal3_test.go): [Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)
  - [x] [Challenge 4](./sets/set1/chal4_test.go): [Detect single-character XOR cipher](https://cryptopals.com/sets/1/challenges/4)
  - [x] [Challenge 5](./sets/set1/chal5_test.go): [Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)
  - [x] [Challenge 6](./sets/set1/chal6_test.go): [Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6) there is a bug here?
  - [x] [Challenge 7](./sets/set1/chal7_test.go): [AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)
  - [x] [Challenge 8](./sets/set1/chal8_test.go): [Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)
- [ ] [Set 2](./sets/set2/): [Block crypto](https://cryptopals.com/sets/2)
  - [x] [Challenge 9](./sets/set2/chal9_test.go): [Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9)
  - [x] [Challenge 10](./sets/set2/chal10_test.go): [Implement CBC mode](https://cryptopals.com/sets/2/challenges/10)
  - [ ] [Challenge 11](./sets/set2/chal11_test.go): [An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11)
  - ...
  - [x] [Challenge 15](./sets/set2/chal15_test.go): [PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)
