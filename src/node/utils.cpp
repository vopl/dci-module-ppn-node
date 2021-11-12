/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "pch.hpp"
#include "utils.hpp"
#include <sys/utsname.h>
#include <pwd.h>

namespace dci::module::ppn::node::utils
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    std::string mkRandomName(size_t chars)
    {
        std::string res;
        res.resize(chars);

        crypto::rnd::generate(res.data(), chars);
        for(char& c : res)
        {
            c = (unsigned(c)%24) + unsigned('a');
        }

        return res;
    }

    namespace
    {
        const std::map<String, std::function<void(const config::ptree& config, crypto::Blake2b& accumuler)>> keyMaterialFetchers =
        {
            {
                "memInfo", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    std::ifstream in{"/proc/meminfo"};
                    std::string line;
                    while(std::getline(in, line))
                    {
                        if(std::string::npos == line.find("Total")) continue;
                        accumuler.add(line);
                    }
                }
            },
            {
                "cpuInfo", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    std::ifstream in{"/proc/cpuinfo"};
                    std::string line;
                    while(std::getline(in, line))
                    {
                        if(std::string::npos != line.find("cpu MHz")) continue;
                        accumuler.add(line);
                    }
                }
            },
            {
                "diskInfo", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    namespace fs = std::filesystem;
                    std::set<fs::directory_entry> des;

                    if(fs::exists("/dev/disk/by-id"))
                    {
                        for(const fs::directory_entry& de : fs::directory_iterator{"/dev/disk/by-id"})
                        {
                            des.insert(de);
                        }
                    }

                    if(fs::exists("/dev/disk/by-uuid"))
                    {
                        for(const fs::directory_entry& de : fs::directory_iterator{"/dev/disk/by-uuid"})
                        {
                            des.insert(de);
                        }
                    }

                    for(const fs::directory_entry& de : des)
                    {
                        accumuler.add(de.path().filename().string());
                    }
                }
            },
            {
                "netMacAddress", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    namespace fs = std::filesystem;
                    std::set<fs::directory_entry> des;
                    for(const fs::directory_entry& de : fs::directory_iterator{"/sys/class/net"})
                    {
                        if(fs::exists(de.path()/"device"))
                        {
                            des.insert(de);
                        }
                    }

                    for(const fs::directory_entry& de : des)
                    {
                        accumuler.add(de.path().filename().string());

                        std::ifstream in{de.path()/"address"};
                        while(in)
                        {
                            std::string address;
                            in >> address;
                            if(!address.empty())
                            {
                                accumuler.add(address);
                            }
                        }
                    }
                }
            },
            {
                "osInfo", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    utsname v;
                    if(uname(&v))
                    {
                        throw api::Error("uname failed: "+std::error_code{errno, std::generic_category()}.message());
                    }

                    accumuler.add("sysname");
                    accumuler.add(v.sysname);

                    accumuler.add("nodename");
                    accumuler.add(v.nodename);

                    accumuler.add("release");
                    accumuler.add(v.release);

                    accumuler.add("version");
                    accumuler.add(v.version);

                    accumuler.add("machine");
                    accumuler.add(v.machine);

                    accumuler.add("kernel cmdline");
                    std::ifstream in{"/proc/cmdline"};
                    std::string line;
                    while(std::getline(in, line))
                    {
                        accumuler.add(line);
                    }
                }
            },
            {
                "appPath", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    char path[PATH_MAX] = {0};
                    if(0 > readlink("/proc/self/exe", path, PATH_MAX-1))
                    {
                        throw api::Error("readlink failed: "+std::error_code{errno, std::generic_category()}.message());
                    }
                    accumuler.add(path);
                }
            },
            {
                "appPid", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    accumuler.add(::getpid());
                }
            },
            {
                "domainname", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    char name[256] = {0};
                    if(getdomainname(name, sizeof(name)-1))
                    {
                        throw api::Error("getdomainname failed: "+std::error_code{errno, std::generic_category()}.message());
                    }
                    accumuler.add(name);
                }
            },
            {
                "hostname", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    char name[256] = {0};
                    if(gethostname(name, sizeof(name)-1))
                    {
                        throw api::Error("gethostname failed: "+std::error_code{errno, std::generic_category()}.message());
                    }
                    accumuler.add(name);
                }
            },
            {
                "username", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    {
                        const char* name = getenv("USER");
                        if(name)
                        {
                            accumuler.add(name);
                            return;
                        }
                    }

                    errno = 0;
                    std::error_code ec_getlogin;
                    {
                        const char* name = getlogin();
                        if(name)
                        {
                            accumuler.add(name);
                            return;
                        }
                        ec_getlogin = std::error_code{errno, std::generic_category()};
                    }

                    errno = 0;
                    std::error_code ec_getpwuid;
                    passwd* pw = getpwuid(geteuid());
                    if(pw)
                    {
                        accumuler.add(pw->pw_name);
                        return;
                    }
                    ec_getpwuid = std::error_code{errno, std::generic_category()};

                    throw api::Error("getlogin failed: "+ec_getlogin.message()+", getpwuid failed: "+ec_getpwuid.message());
                }
            },
            {
                "random", [](const config::ptree&, crypto::Blake2b& accumuler)
                {
                    char buf[256];
                    if(!crypto::rnd::generate(buf, sizeof(buf)))
                    {
                        throw api::Error("crypto::rnd failed");
                    }
                    accumuler.add(buf, sizeof(buf));
                }
            },
            {
                "constant", [](const config::ptree& config, crypto::Blake2b& accumuler)
                {
                    accumuler.add(config.get_value(String{}));
                }
            },
        };
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    api::link::Key parseKey(const config::ptree& config)
    {
        api::link::Key res;

        crypto::Blake2b accumuler{res.size()};

        auto tryOne = [&](const String& kind, const config::ptree& conf = config::ptree{})
        {
            auto iter = keyMaterialFetchers.find(kind);
            if(keyMaterialFetchers.end() != iter)
            {
                accumuler.add(kind);
                iter->second(conf, accumuler);
                accumuler.barrier();
            }
            else
            {
                throw api::Error("ppn node: bad key material kind: "+kind);
            }
        };

        {
            String kind = config.get_value(String{});
            if(kind.empty() || "auto" == kind)
            {
                tryOne("memInfo");
                tryOne("cpuInfo");
                tryOne("diskInfo");
                tryOne("netMacAddress");
                tryOne("osInfo");

                tryOne("appPath");

                tryOne("domainname");
                tryOne("hostname");
                tryOne("username");

                tryOne("constant", config::ptree{String{"auto"}});
            }
            else
            {
                tryOne(kind);
            }
        }

        for(const auto&[kind, child] : config)
        {
            tryOne(kind, child);
        }

        dbgAssert(accumuler.digestSize() == res.size());
        accumuler.finish(res.data());
        return res;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    bool parseBool(const String& param)
    {
        static const std::regex t("^(t|true|on|enable|allow|1)$", std::regex_constants::icase | std::regex::optimize);
        static const std::regex f("^(f|false|off|disable|deny|0)$", std::regex_constants::icase | std::regex::optimize);

        if(std::regex_match(param, t)) return true;
        if(std::regex_match(param, f)) return false;

        throw api::Error("bad node boolean value provided: "+param);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    uint16 parseUint16(const String& param)
    {
        return static_cast<uint16>(std::stoull(param));
    }
}
