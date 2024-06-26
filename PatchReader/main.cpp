#include "binaryninjacore.h"
#include "binaryninjaapi.h"

#include <fstream>
#include <sstream>
#

using namespace BinaryNinja;

void Execution(BinaryView* View)
{
	std::string Result;

	GetOpenFileNameInput(Result, "Select Patch File", "*.1337");

	if (Result.empty())
	{
		Log(WarningLog, "No File was Selected >:C");
		return;
	}

	Log(InfoLog, "%s", Result.c_str());

	// Read File
	std::ifstream File(Result);

	if (!File.is_open())
	{
		Log(WarningLog, "Failed to open File, Doesn't Exist?");
		return;
	}

	std::string Line;

	BOOLEAN SkipFirst = TRUE;

	while (std::getline(File, Line))
	{
		if (SkipFirst)
		{
			SkipFirst = FALSE;
			continue;
		}

		// Grab Hex value from before the : symbol & convert to hex :D
		std::string HexValue = Line.substr(0, Line.find(":"));
		ULONG Result = std::stoul(HexValue.c_str(), 0, 16);

		// Log(InfoLog, "0x%X > %s", Result, HexValue.c_str());

		std::vector<Ref<Function>> function = View->GetAnalysisFunctionsContainingAddress(Result);

		for (unsigned int i = 0; i < function.size(); i++)
		{
			if (function.size() == 0)
			{
				Log(InfoLog, "No Function at Address > 0x%6X", Result);
				continue;
			}

			function[i]->SetUserInstructionHighlight(View->GetDefaultArchitecture(), Result, RedHighlightColor);
			Log(InfoLog, "Address Highlighted > 0x%llx", Result);
		}
	}

	File.close();

	return;


	// Allocate Memory

	// Read from second line
}


extern "C"
{
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit()
{
	PluginCommand::Register("Cheese", "Cheese",
		[](BinaryView* View) { Execution(View); });


	LogInfo("Setup for Test Sig Scanner has been Created");
	return true;
}
}
