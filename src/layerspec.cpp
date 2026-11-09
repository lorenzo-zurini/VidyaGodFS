#include "layerspec.h"

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
            else { Err = "unknown layer type: " + Type; return false; }
            LS.source  = L.at("source").get<std::string>();
            LS.target  = NormalizeVPath(L.value("target", std::string()));
            //A zip's or delta's own CID: what a delta names it by. A delta's bases: the CIDs of the files whose bytes,
            //joined in this order, it was built over — REQUIRED, none twice. A malformed shape is REFUSED rather than
            //repaired (a base dropped is a base of the wrong bytes); a base no layer here carries is the plan's to
            //report (PlanTree), and costs only that delta.
            const size_t Self = Out.layers.size();
            const auto Bad = [&](const std::string &Why) { Err = "layer " + std::to_string(Self) + ": " + Why; return false; };
            const bool Archive = LS.type == LayerType::Zip || LS.type == LayerType::Delta;
            if (L.contains("cid"))
            {
                if (!Archive) return Bad("only a zip or a delta has a cid");
                if (!L["cid"].is_string() || L["cid"].get<std::string>().empty()) return Bad("cid must be a non-empty string");
                LS.cid = L["cid"].get<std::string>();
            }
            if (L.contains("bases") != (LS.type == LayerType::Delta))
                return Bad(L.contains("bases") ? "only a delta has bases" : "a delta must name its bases");
            if (LS.type == LayerType::Delta)
            {
                if (!L["bases"].is_array()) return Bad("bases must be an array of CIDs");   // empty: the plan reports it
                for (const auto &B : L["bases"])
                {
                    if (!B.is_string() || B.get<std::string>().empty()) return Bad("a base must be a CID");
                    if (std::find(LS.bases.begin(), LS.bases.end(), B.get<std::string>()) != LS.bases.end())
                        return Bad("base " + B.get<std::string>() + " is named twice");
                    LS.bases.push_back(B.get<std::string>());
                }
            }
            LS.rw      = L.value("rw", false);
            LS.bytesOnly = L.value("bytesOnly", false);
            if (LS.bytesOnly && !Archive)
                return Bad("only a zip or a delta can be bytes-only");
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
    }
    catch (const std::exception &E) { Err = std::string("spec field error: ") + E.what(); return false; }

    if (Out.mountpoint.empty()) { Err = "spec has empty mountpoint"; return false; }
    return true;
}
