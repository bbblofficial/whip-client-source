

#include <stdio.h>
#include <stdint.h>
#include "../../../includes/util/algorithm/AESEAlgorithm.h"

#define Nk 4

#define Nb 4

#define Nr 10

static unsigned char stateMatrix[4][4];

static unsigned char roundKeys[Nb * Nk * (Nr + 1)];

static unsigned char roundNumber;

#define xtime(a) ( ((a) & 0x80) ? (((a) << 1) ^ 0x1b) : ((a) << 1) )

static const unsigned char sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char rcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10,
	0x20, 0x40, 0x80, 0x1b, 0x36
};

static void SubWord(unsigned char word[4]) {
	word[0] = sbox[word[0]];
	word[1] = sbox[word[1]];
	word[2] = sbox[word[2]];
	word[3] = sbox[word[3]];
}

static void RotWord(unsigned char word[4]) {
	unsigned char tempRot;

	tempRot = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tempRot;
}

static void KeyExpansion128(const unsigned char *key) {
	unsigned char temp[4], i, j;

	for (i = 0; i < Nb * Nk; i++) {
		roundKeys[i] = key[i];
	}

	for (; i < Nb * Nk * (Nr + 1); i++)
	{
		if (i % (Nk * Nb) == 0)
		{
			temp[0] = roundKeys[(i - Nk) + 0];
			temp[1] = roundKeys[(i - Nk) + 1];
			temp[2] = roundKeys[(i - Nk) + 2];
			temp[3] = roundKeys[(i - Nk) + 3];

			RotWord(temp);
			SubWord(temp);

			temp[0] = temp[0] ^ rcon[i / (Nk * Nb) - 1];

			roundKeys[i + 0] = roundKeys[i - (Nb * Nk) + 0] ^ temp[0];

			roundKeys[i + 1] = roundKeys[i - (Nb * Nk) + 1] ^ temp[1];

			roundKeys[i + 2] = roundKeys[i - (Nb * Nk) + 2] ^ temp[2];

			roundKeys[i + 3] = roundKeys[i - (Nb * Nk) + 3] ^ temp[3];

			i += 3;

		} else {
			roundKeys[i] = roundKeys[i - Nk] ^ roundKeys[i - (Nb * Nk)];

		}
	}

}

static void AddRoundKey() {
	unsigned char tempRoundKeys[4][4], i, j, tempArray[4];

	for (i = 0; i < Nb; i++) {
		tempArray[0] = roundKeys[Nk * (i + roundNumber * Nb) + 0];

		tempArray[1] = roundKeys[Nk * (i + roundNumber * Nb) + 1];

		tempArray[2] = roundKeys[Nk * (i + roundNumber * Nb) + 2];

		tempArray[3] = roundKeys[Nk * (i + roundNumber * Nb) + 3];

		for (j = 0; j < Nb; j++) {
			tempRoundKeys[j][i] = tempArray[j];
		}
	}

	for (i = 0; i < Nb; i++) {
		for (j = 0; j < Nb; j++) {
			stateMatrix[i][j] = stateMatrix[i][j] ^ tempRoundKeys[i][j];

		}
	}

}

static void SubBytes() {
	unsigned char i, j;

	for (i = 0; i < Nb; i++) {
		for (j = 0; j < Nb; j++) {
			stateMatrix[i][j] = sbox[stateMatrix[i][j]];
		}
	}

}

static void ShiftRows() {
	unsigned char tempRow;

	tempRow = stateMatrix[1][0];
	stateMatrix[1][0] = stateMatrix[1][1];
	stateMatrix[1][1] = stateMatrix[1][2];
	stateMatrix[1][2] = stateMatrix[1][3];
	stateMatrix[1][3] = tempRow;

	tempRow = stateMatrix[2][0];
	stateMatrix[2][0] = stateMatrix[2][2];
	stateMatrix[2][2] = tempRow;

	tempRow = stateMatrix[2][1];
	stateMatrix[2][1] = stateMatrix[2][3];
	stateMatrix[2][3] = tempRow;

	tempRow = stateMatrix[3][3];
	stateMatrix[3][3] = stateMatrix[3][2];
	stateMatrix[3][2] = stateMatrix[3][1];
	stateMatrix[3][1] = stateMatrix[3][0];
	stateMatrix[3][0] = tempRow;
}

static void MixColumns() {
	unsigned char i, j, tempCell[4];

	for (i = 0; i < Nb; i++) {
		tempCell[0] = (xtime(stateMatrix[0][i])
		               ^ (xtime(stateMatrix[1][i]) ^ stateMatrix[1][i])
		               ^ (stateMatrix[2][i])
		               ^ (stateMatrix[3][i]));

		tempCell[1] = (stateMatrix[0][i]
		               ^ (xtime(stateMatrix[1][i]))
		               ^ (xtime(stateMatrix[2][i]) ^ stateMatrix[2][i])
		               ^ (stateMatrix[3][i]));

		tempCell[2] = (stateMatrix[0][i]
		               ^ stateMatrix[1][i]
		               ^ (xtime(stateMatrix[2][i]))
		               ^ (xtime(stateMatrix[3][i]) ^ stateMatrix[3][i]));

		tempCell[3] = ((xtime(stateMatrix[0][i]) ^ stateMatrix[0][i])
		               ^ stateMatrix[1][i]
		               ^ stateMatrix[2][i]
		               ^ (xtime(stateMatrix[3][i])));

		for (j = 0; j < Nb; j++) {
			stateMatrix[j][i] = tempCell[j];
		}
	}
}

void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) {
	KeyExpansion128(k);

	for (unsigned char i = 0; i < Nb; i++) {
		for (unsigned char j = 0; j < Nb; j++) {
			stateMatrix[j][i] = p[(i * Nb) + j];

		}
	}

	roundNumber = 0;
	AddRoundKey();

	for (roundNumber = 1; roundNumber < Nr; ++roundNumber) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey();

	}

	SubBytes();
	ShiftRows();
	AddRoundKey();

	for (unsigned char i = 0; i < Nb; i++) {
		for (unsigned char j = 0; j < Nb; j++) {
			c[(i * Nb) + j] = stateMatrix[j][i];
		}
	}

}
