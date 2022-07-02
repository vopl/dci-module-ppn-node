/* This file is part of the the dci project. Copyright (C) 2013-2022 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "pch.hpp"
#include "daemon.hpp"

namespace dci::module::ppn::node
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Daemon::Daemon()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Daemon::~Daemon()
    {
        _node.reset();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Daemon::startImpl(idl::Config&& config)
    {
        _node.reset(new Node);
        _node->start(std::move(config));
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Daemon::stopImpl()
    {
        if(_node)
        {
            _node->stop();
            _node.reset();
        }
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    idl::Interface Daemon::serviceImpl()
    {
        return idl::Interface{_node->opposite()};
    }
}
