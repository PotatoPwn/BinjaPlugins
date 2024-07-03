#include <vector>
#include <sstream>
#include <fstream>


#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;

std::vector<int> ConvertToBytes(std::string& Input)
{
	std::vector<int> Output;

	for (unsigned int i = 0; i < Input.size(); i += 2)
	{
		std::string ByteString = Input.substr(i, 2);
		if (ByteString.find("??") != std::string::npos)
		{
			Output.push_back(-1);
			continue;
		}

		int Value;
		try
		{
			// Convert to Hex
			Value = std::stoi(ByteString, 0, 16);
		}
		catch (...)
		{
			Log(ErrorLog, "Error Occured Converting to Hex > %s", ByteString.c_str());
			Value = -1;
		}
		Output.push_back(Value);
	}
	return Output;
}


void Execution(BinaryView* View)
{
	std::string Result;

	// Read PatternList File
	GetOpenFileNameInput(Result, "PatternList File");

	if (Result.empty())
	{
		Log(WarningLog, "No File Provided");
		return;
	}

	Log(InfoLog, "File Selected at %s", Result.c_str());

	std::ifstream File(Result);

	if (!File.is_open())
	{
		Log(WarningLog, "Failed to open File, Doesn't Exist?");
		return;
	}

	// Get Binary Process Information
	uint64_t BinStart = View->GetStart();
	uint64_t BinEnd = View->GetEnd();
	uint64_t BinSize = BinEnd - BinStart;

	// Start Main Function Loop
	std::string PatternLine;
	while (std::getline(File, PatternLine))
	{
		// Convert the Pattern Strings into Hex Values
		std::vector<int> HexValue = ConvertToBytes(PatternLine);
		if (HexValue.empty())
		{
			Log(WarningLog, "Error Converting Pattern to Hex > %s", PatternLine.c_str());
			continue;
		}

		// Find the patterns & store the results into a vector array for later processing
		auto HuntSig = [&]() -> std::vector<uint64_t>
		{
			bool FoundFirstMatch = FALSE;
			uint64_t FoundStartAddress = 0;
			uint64_t Index = 0;
			unsigned char ReadBytes = 0;

			std::vector<uint64_t> Result;

			for (uint64_t i = BinStart; i < BinEnd && Index < HexValue.size(); i++)
			{
				View->Read(&ReadBytes, i, 2);

				if (HexValue[Index] == ReadBytes || HexValue[Index] == -1)
				{
					// Found First Byte to Match
					if (!FoundFirstMatch)
					{
						FoundFirstMatch = true;
						FoundStartAddress = i;
					}
					// Increment Index of Search Bytes
					Index++;

					// Check if the Index is the same size as the Size (Meaning its completed)
					if (Index == HexValue.size())
					{
						// Store in Vector
						Result.push_back(FoundStartAddress);
						FoundFirstMatch = false;
						Index = 0;
					}
				}
				else if (FoundFirstMatch)
				{
					FoundFirstMatch = false;
					// Reset Index
					Index = 0;
					i = FoundStartAddress;
				}
			}
			return Result;
		};

		// Process Results :)
		std::vector<uint64_t> SigHuntResults = HuntSig();
		if (SigHuntResults.empty())
			continue;

		// Begin Nopping / Highlighting
		for (unsigned int i = 0; i < SigHuntResults.size(); i++)
		{
			uint64_t j = SigHuntResults[i];
			for (j; j < SigHuntResults[i] + HexValue.size(); j++)
			{
				// Ensure Opcode sits within a function, not in data function
				std::vector<Ref<Function>> function = View->GetAnalysisFunctionsContainingAddress(j);
				if (function.empty())
					continue;

				Ref<Architecture> Archtype = Architecture::GetByName("x86_64");
				size_t Size = View->GetInstructionLength(Archtype, j);

				// Size of Opcode Must equal opcode size, ie no funny business :)
				if (Size != HexValue.size())
					continue;

				// todo Highlight for now, eventually make it so i can either Highlight or NOP
				function[0]->SetUserInstructionHighlight(View->GetDefaultArchitecture(), j, RedHighlightColor);
				Log(InfoLog, "Size > %d, Address >  %x, Pattern > %s", Size, j, PatternLine.c_str());
			}
		}
	}
	// Cleanup
	File.close();

	return;
}

extern "C"
{
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit()
{
	PluginCommand::Register("PatternPatcher", "Reads a File with patterns and NOPS Accordingly",
		[](BinaryView* View) { Execution(View); });


	LogInfo("Setup for Test Sig Scanner has been Created");
	return true;
}
}
