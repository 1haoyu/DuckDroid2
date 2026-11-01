// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/debug/target_xml.hpp"

#include <cstdio>

namespace duckemu::runtime::debug
{

std::string aarch64TargetXml()
{
	std::string xml;
	xml += "<?xml version=\"1.0\"?>\n";
	xml += "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
	xml += "<target>\n";
	xml += "  <architecture>aarch64</architecture>\n";
	xml += "  <feature name=\"org.gnu.gdb.aarch64.core\">\n";
	for (int i = 0; i < 31; ++i)
	{
		char line[96] = {};
		std::snprintf(line, sizeof(line),
			"    <reg name=\"x%d\" bitsize=\"64\" type=\"int\" regnum=\"%d\"/>\n", i, i);
		xml += line;
	}
	xml += "    <reg name=\"sp\" bitsize=\"64\" type=\"data_ptr\" regnum=\"31\"/>\n";
	xml += "    <reg name=\"pc\" bitsize=\"64\" type=\"code_ptr\" regnum=\"32\"/>\n";
	xml += "    <reg name=\"cpsr\" bitsize=\"32\" type=\"int\" regnum=\"33\"/>\n";
	xml += "  </feature>\n";
	xml += "</target>\n";
	return xml;
}

} // namespace duckemu::runtime::debug
