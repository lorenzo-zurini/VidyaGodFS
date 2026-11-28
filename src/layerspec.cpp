#include "layerspec.h"
#include "coding.h"

#include <algorithm>

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>

std::string NormalizeVPath(const std::string &Path)
{
    size_t a = 0, b = Path.size();
    while (a < b && Path[a] == '/') ++a;
    while (b > a && Path[b - 1] == '/') --b;
    return Path.substr(a, b - a);
}

std::string CleanMemberName(const std::string &Raw)
{
    //'\\' is a separator (as the app's validator and launch tree read it), a "." part and an empty one are nothing
    //("./Bin/" is "Bin", as the kernel resolves it); a ".." part names outside the archive's folder — no name at all.
    std::string P = Raw;
    for (char &C : P) if (C == '\\') C = '/';
    std::string Out;
    size_t From = 0;
    for (;;)
    {
        const size_t To = P.find('/', From);
        const std::string Part = P.substr(From, To == std::string::npos ? std::string::npos : To - From);
        if (Part == "..") return {};
        if (!Part.empty() && Part != ".") Out += (Out.empty() ? "" : "/") + Part;
        if (To == std::string::npos) return Out;
        From = To + 1;
    }
}

bool SafeMemberName(const std::string &VRel) { return !VRel.empty() && CleanMemberName(VRel) == VRel; }

bool ParseSpec(const std::string &Path, Spec &Out, std::string &Err)
{
    std::ifstream In(Path, std::ios::binary);
    if (!In) { Err = "cannot open spec file: " + Path; return false; }
    std::stringstream Text;
    Text << In.rdbuf();
    return ParseSpecText(Text.str(), Out, Err);
}

bool ParseSpecText(const std::string &Text, Spec &Out, std::string &Err)
{
    nlohmann::json J;
    try { J = nlohmann::json::parse(Text); }
    catch (const std::exception &E) { Err = std::string("spec JSON parse error: ") + E.what(); return false; }

    try
    {
        Out.mountpoint = J.at("mountpoint").get<std::string>();
        Out.uid        = J.value("uid", 1000u);
        Out.gid        = J.value("gid", 1000u);
        Out.readOnly   = J.value("readonly", false);
        Out.launchMounts = std::max(1, J.value("launchMounts", 1));
#ifdef _WIN32
        Out.caseInsensitive = J.value("caseInsensitive", true);    // Windows programs name files in any case
#else
        Out.caseInsensitive = J.value("caseInsensitive", false);
#endif
        if (!Out.readOnly && J.contains("writelayer") && !J["writelayer"].is_null())
            Out.writelayer = J["writelayer"].get<std::string>();

        for (const auto &L : J.at("layers"))
        {
            LayerSpec LS;
            std::string Type = L.at("type").get<std::string>();
            if      (Type == "dir")   LS.type = LayerType::Dir;
            else if (Type == "zip")   LS.type = LayerType::Zip;
            else if (Type == "file")  LS.type = LayerType::File;
            else if (Type == "delta") LS.type = LayerType::Delta;   // a .vgdelta over the earlier layers it names (`bases`)
            else if (Type == "coded") LS.type = LayerType::Coded;   // a stream coded back from its content (`bases`) and decisions
            else if (Type == "view")  LS.type = LayerType::View;    // the files a listing finds in a content (`bases`)
            else if (Type == "tree")  LS.type = LayerType::Tree;    // files over the bytes of its `bases` (a .vgtz)
            else { Err = "unknown layer type: " + Type; return false; }
            LS.source  = L.at("source").get<std::string>();
            LS.target  = NormalizeVPath(L.value("target", std::string()));
            //A zip's or delta's own CID: what a delta names it by. A delta's bases: the CIDs of the files whose bytes,
            //joined in this order, it was built over — REQUIRED, none twice. A malformed shape is REFUSED rather than
            //repaired (a base dropped is a base of the wrong bytes); a base no layer here carries is the plan's to
            //report (PlanTree), and costs only that delta.
            const size_t Self = Out.layers.size();
            const auto Bad = [&](const std::string &Why) { Err = "layer " + std::to_string(Self) + ": " + Why; return false; };
            //A layer of bytes — a zip, a delta, a single file (a disc image a delta is built over): what a delta names by CID.
            const bool Bytes = LS.type == LayerType::Zip || LS.type == LayerType::Delta || LS.type == LayerType::File || LS.type == LayerType::Coded;
            const bool Rebuilt = LS.type == LayerType::Delta || LS.type == LayerType::Coded || LS.type == LayerType::View || LS.type == LayerType::Tree;
            if (L.contains("cid"))
            {
                if (!Bytes && LS.type != LayerType::View && LS.type != LayerType::Tree) return Bad("only a zip, a delta, a file, a view or a tree has a cid");
                if (!L["cid"].is_string() || L["cid"].get<std::string>().empty()) return Bad("cid must be a non-empty string");
                LS.cid = L["cid"].get<std::string>();
            }
            if (L.contains("bases") != Rebuilt)
                return Bad(L.contains("bases") ? "only a delta, a coded stream, a view or a tree has bases" : "a delta, a coded stream, a view or a tree must name its bases");
            if (Rebuilt)
            {
                //null: the layer named no base (its node has none, or a malformed list): the plan reports it and mounts none
                //of it. An EMPTY list is a delta over nothing: its bytes are its own (a file stored compressed).
                if (L["bases"].is_null() && LS.type == LayerType::Delta) LS.basesNamed = false;
                else if (!L["bases"].is_array()) return Bad("bases must be an array of CIDs");
                for (const auto &B : L["bases"].is_array() ? L["bases"] : nlohmann::json::array())
                {
                    if (!B.is_string() || B.get<std::string>().empty()) return Bad("a base must be a CID");
                    if (std::find(LS.bases.begin(), LS.bases.end(), B.get<std::string>()) != LS.bases.end())
                        return Bad("base " + B.get<std::string>() + " is named twice");
                    LS.bases.push_back(B.get<std::string>());
                }
            }
            if (LS.type == LayerType::View && LS.bases.size() != 1) return Bad("a view names exactly one base: its content");
            if (LS.type == LayerType::Coded)
            {
                if (LS.bases.size() != 1) return Bad("a coded stream names exactly one base: its content");
                //its description: the layer's own DESCRIPTION, carried whole (MetaPackageFormat 04, 22.16)
                if (!L.contains("description") || !L["description"].is_object() || L["description"].empty())
                    return Bad("a coded stream needs its description (its layer's DESCRIPTION)");
                { coding::Description D; std::string Why;
                  if (!coding::Read(L["description"].dump(), D, Why)) return Bad("a coded stream's description does not read: " + Why); }
                if (!L.contains("name") || !L["name"].is_string() || NormalizeVPath(L["name"].get<std::string>()).empty()) return Bad("a coded stream needs the name it appears by");
                LS.description = L["description"].dump();
                LS.name = NormalizeVPath(L["name"].get<std::string>());
            }
            else if (L.contains("description") || L.contains("name")) return Bad("only a coded stream has a description and a name");
            if (L.contains("hide"))
            {
                if (!L["hide"].is_array()) return Bad("hide must be an array of paths");
                for (const auto &H : L["hide"])
                {
                    if (!H.is_string() || NormalizeVPath(H.get<std::string>()).empty()) return Bad("a hidden path must be a non-empty path");
                    LS.hide.push_back(NormalizeVPath(H.get<std::string>()));
                }
            }
            LS.rw      = L.value("rw", false);
            if (LS.rw && !LS.hide.empty()) return Bad("a read-write folder hides nothing (it is the user's)");
            LS.bytesOnly = L.value("bytesOnly", false);
            LS.fixed   = L.value("fixed", false);
            if (LS.bytesOnly && !Bytes && LS.type != LayerType::View && LS.type != LayerType::Tree)
                return Bad("only a zip, a delta, a file, a coded stream, a view or a tree can be read only for its bytes or files");
            // SUBMOUNTS: array of Docker-style "src:dst" strings → (source,target) pairs (split on first ':').
            if (L.contains("submounts") && L["submounts"].is_array())
                for (const auto &E : L["submounts"])
                {
                    if (!E.is_string()) continue;
                    const std::string S = E.get<std::string>();
                    const size_t C = S.find(':');
                    if (C == std::string::npos)
                    {
                        std::cerr << "[vidyagodfs] ignoring malformed submount (no ':'): " << S << "\n";
                        continue;
                    }
                    LS.submounts.emplace_back(NormalizeVPath(S.substr(0, C)), NormalizeVPath(S.substr(C + 1)));
                }
            Out.layers.push_back(std::move(LS));
        }
        //"patches": [{ "path": "game/x.iso", "at": 542052, "bytes": "07" }] — refused whole when one is malformed (a patch
        //half taken serves a file neither the game's nor the package's).
        if (J.contains("patches"))
        {
            if (!J["patches"].is_array()) { Err = "patches must be an array"; return false; }
            for (const auto &P : J["patches"])
            {
                BytePatch B;
                const std::string Hex = P.is_object() && P.contains("bytes") && P["bytes"].is_string() ? P["bytes"].get<std::string>() : std::string();
                if (!P.is_object() || !P.contains("path") || !P["path"].is_string() || !P.contains("at")
                    || !P["at"].is_number_unsigned() || Hex.empty() || Hex.size() % 2 != 0)
                { Err = "a patch is { path, at, bytes (hex) }: " + P.dump(); return false; }
                B.path = NormalizeVPath(P["path"].get<std::string>());
                B.at = P["at"].get<uint64_t>();
                for (size_t I = 0; I < Hex.size(); I += 2)
                {
                    const auto Nib = [](char C) { return C >= '0' && C <= '9' ? C - '0' : C >= 'a' && C <= 'f' ? C - 'a' + 10 : C >= 'A' && C <= 'F' ? C - 'A' + 10 : -1; };
                    const int Hi = Nib(Hex[I]), Lo = Nib(Hex[I + 1]);
                    if (Hi < 0 || Lo < 0) { Err = "a patch's bytes are not hex: " + Hex; return false; }
                    B.bytes.push_back((uint8_t)(Hi << 4 | Lo));
                }
                if (B.path.empty() || B.at + B.bytes.size() < B.at) { Err = "a patch names no file, or runs past the end of numbers: " + P.dump(); return false; }
                Out.patches.push_back(std::move(B));
            }
        }
    }
    catch (const std::exception &E) { Err = std::string("spec field error: ") + E.what(); return false; }

    if (Out.mountpoint.empty()) { Err = "spec has empty mountpoint"; return false; }
    return true;
}
