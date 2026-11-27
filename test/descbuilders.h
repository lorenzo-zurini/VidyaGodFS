// TEST FIXTURES: descriptions built by code, for the tests only (the engine carries no format: a package's descriptions
// are data in its nodes, MetaPackageFormat chapter 22 §22.16). Each is what the reference node text of the same name says.
#pragma once
#include "coding.h"

namespace coding {

Description LzmaDescription(int Lc, int Lp, int Pb, uint32_t Dict, bool EndMarker);
// Knob: a zlib family that predicts the stream's tokens (level | memLevel << 8 | windowBits << 16: zlib's default is
// 6 | 8 << 8 | 15 << 16), 0 none.
Description DeflateDescription(uint32_t Knob = 0);
// An Inno Setup installer (5.1.5 or later; GOG's): the loader stub
// and everything outside the chunks as it is, each zlib chunk's deflate stream through the zlib family (Knob as above),
// each LZMA2 chunk walked by its chunk headers (its inside as it is).
Description InnoDescription(uint32_t Knob = 6 | 8 << 8 | 15 << 16);
Description Lz4BlockDescription();
// Bethesda archive v105 (Skyrim SE): header region + members, LZ4 frames. Attempts: the LZ4 high-compression family that
// predicts the frames' blocks (32768: Bethesda's own packer, lz4 1.7 level 16), 0 none (every sequence a decision).
Description BsaDescription(uint32_t Attempts = 32768);

}  // namespace coding
