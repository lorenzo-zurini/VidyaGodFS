#include "layerspec.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

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

    nlohmann::json J;
    try { In >> J; }
    catch (const std::exception &E) { Err = std::string("spec JSON parse error: ") + E.what(); return false; }

    try
    {
        Out.mountpoint = J.at("mountpoint").get<std::string>();
        Out.uid        = J.value("uid", 1000u);
        Out.gid        = J.value("gid", 1000u);
        Out.readOnly   = J.value("readonly", false);
        if (!Out.readOnly && J.contains("writelayer") && !J["writelayer"].is_null())
            Out.writelayer = J["writelayer"].get<std::string>();

        for (const auto &L : J.at("layers"))
        {
            LayerSpec LS;
            std::string Type = L.at("type").get<std::string>();
            if      (Type == "dir")  LS.type = LayerType::Dir;
            else if (Type == "zip")  LS.type = LayerType::Zip;
            else if (Type == "file") LS.type = LayerType::File;
            else { Err = "unknown layer type: " + Type; return false; }
            LS.source = L.at("source").get<std::string>();
            LS.target = NormalizeVPath(L.value("target", std::string()));
            LS.rw     = L.value("rw", false);
            Out.layers.push_back(std::move(LS));
        }
    }
    catch (const std::exception &E) { Err = std::string("spec field error: ") + E.what(); return false; }

    if (Out.mountpoint.empty()) { Err = "spec has empty mountpoint"; return false; }
    return true;
}
