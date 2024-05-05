#include <algorithm>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"

#include "PatternList.h"

using namespace BinaryNinja;

// Forward Declaration


// Global Declaration

std::vector<int> ConvertToByte(std::string& Input)
{
	std::vector<int> Output;

	for (unsigned int i = 0; i < Input.size(); i += 2)
	{
		std::string ByteString = Input.substr(i, 2);
		if (ByteString.find('?') != std::string::npos)
		{
			// Convert ? strings to the hex value of F
			std::replace(ByteString.begin(), ByteString.end(), '?', 'F');
		}

		int Value;
		try
		{
			// Convert to Hex
			Value = std::stoi(ByteString, nullptr, 16);
		}
		catch (...)
		{
			Log(ErrorLog, "Error Occured Converting to Hex");
			Value = 0xF;
		}

		Output.push_back(Value);
	}

	return Output;
}

void FindSig(BinaryView* View)
{
	// Essential for Threading (Thanks for Emesare & GalenBwill on Binja slack for this)
	Ref<BinaryView> ViewRef = View;

	for (unsigned int i = 0; i < DeadCode.size(); i++)
	{
		std::string InputData = DeadCode[i];


		// Testing Area


		if (InputData.empty())
		{
			Log(ErrorLog, "Input Data Empty");
			return;
		}

		std::vector<int> HexArray = ConvertToByte(InputData);
		if (HexArray.empty())
		{
			Log(ErrorLog, "Unable to Convert to Hex Value");
			return;
		}

		uint64_t BinStart = ViewRef->GetStart();
		uint64_t BinEnd = ViewRef->GetEnd();
		uint64_t BinSize = BinEnd - BinStart;

		//Log(InfoLog, "bin_start = 0x%llx", BinStart);
		//Log(InfoLog, "bin_end = 0x%llx", BinEnd);
		//Log(InfoLog, "bin_size = 0x%llx", BinSize);

		// Begin Searching Process
		// https://github.com/rikodot/binja_native_sigscan/blob/main/sigscan.cpp#L375

		auto HuntSig = [&](uint64_t StartAddress) -> std::vector<uint64_t>
		{
			bool FoundFirstMatch = false;
			uint64_t FoundStartAddress = 0;
			uint64_t Index = 0;
			unsigned char ReadBytes = 0;

			std::vector<uint64_t> ResultA = { 0 };

			for (uint64_t i = StartAddress; i < BinEnd && Index < HexArray.size(); i++)
			{
				// Read Value
				ViewRef->Read(&ReadBytes, i, HexArray.size());

				// if Match
				if (HexArray[Index] == ReadBytes || HexArray[Index] == 0xFF)
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
					if (Index == HexArray.size())
					{
						// Store in Vector
						ResultA.push_back(FoundStartAddress);
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
			return ResultA;
			//return FoundStartAddress;
		};

		// Configure Archtecture for NOP Function
		Ref<Architecture> Archtype = Architecture::GetByName("x86_64");

		std::vector<uint64_t> Result = HuntSig(BinStart);

		if (Result.empty())
		{
			Log(InfoLog, "No Results found for > %s", InputData.c_str());
		}
		else
		{
			for (unsigned int i = 0; i < Result.size(); i++)
			{
				size_t Size = ViewRef->GetInstructionLength(Archtype, Result[i]);
				if (Size == HexArray.size())
				{
					//ViewRef->ConvertToNop(Archtype, Result[i]);
					Log(InfoLog, "Nopped 0x%llx", Result[i]);
				}
			}
		}
		Log(InfoLog, "Finished Clearing %s", InputData.c_str());
	}
}


void ExecutionList(BinaryView* View)
{
	auto HuntWrap = [&]() -> void
	{
		FindSig(View);
	};
	//bruh();
	WorkerEnqueue(HuntWrap, "Bruh");

	Log(InfoLog, "Hunt has Started!");
}

extern "C"
{
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit()
{
	PluginCommand::Register("Search for Sig", "Input SigHere...",
		[](BinaryView* View) { ExecutionList(View); });

	LogInfo("Setup for Test Sig Scanner has been Created");
	return true;
}
}
