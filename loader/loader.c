#include "loader.h"

// uncomment this #define for verbose output from the loader
//#define L_VERBOSE 0

int loader(uint8_t * data)
{
	// Get the PE and section headers
	PIMAGE_DOS_HEADER DOS_header = (PIMAGE_DOS_HEADER)data;
	PIMAGE_NT_HEADERS NT_header = (PIMAGE_NT_HEADERS)((BYTE*)DOS_header + DOS_header->e_lfanew);
	PIMAGE_FILE_HEADER PE_header = (PIMAGE_FILE_HEADER)&NT_header->FileHeader;
	PIMAGE_OPTIONAL_HEADER OPT_header = (PIMAGE_OPTIONAL_HEADER)&NT_header->OptionalHeader;
	//PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)((BYTE*)OPT_header + PE_header->SizeOfOptionalHeader);

	// Get information from PE headers
	DWORD imageBase = OPT_header->ImageBase;
	DWORD sizeOfImage = OPT_header->SizeOfImage;
	DWORD sectionAlignment = OPT_header->SectionAlignment;
	WORD numberOfSections = PE_header->NumberOfSections;
	DWORD sizeOfHeaders = OPT_header->SizeOfHeaders;

	// Get sections from PE image
	PIMAGE_SECTION_HEADER * sectionHeaders; // array of pointers to IMAGE_SECTION_HEADER structs
	sectionHeaders = malloc(sizeof(PIMAGE_SECTION_HEADER) * numberOfSections);
	for (int i = 0; i < numberOfSections; i++) {
		int headerOffset = sizeof(IMAGE_SECTION_HEADER) * i;
		sectionHeaders[i] = (PIMAGE_SECTION_HEADER)((BYTE*)OPT_header + PE_header->SizeOfOptionalHeader + headerOffset);
#ifdef L_VERBOSE
		printf("\t[ ] Found section \"%s\"\n", sectionHeaders[i]->Name);
#endif
	}

	// Reserve memory for program
	// Attempt to get prefered base address. If cannot calculate offset.
	// thank you again stack overflow - https://stackoverflow.com/questions/40936534/how-to-alloc-a-executable-memory-buffer
	// same goes to the MSDN docs on VirtualAlloc - https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc
	// and an MSDN example for VirtualAlloc - https://docs.microsoft.com/en-us/windows/desktop/memory/reserving-and-committing-memory
	uint8_t * progMemory = imageBase;
#ifdef L_VERBOSE
	printf("\t[ ] Attempting to allocate memory starting at: %x\n", progMemory);
#endif
	progMemory = VirtualAlloc(progMemory, sizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (progMemory != imageBase) {
		printf("\t[-] Couldn't allocate memory at preferred base address. Using random base address instead\n");
		progMemory = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		if (progMemory == NULL) {
			printf("\t[-] Couldn't allocate memory at OS-selected address\n");
			return FALSE;
		}
	}
#ifdef L_VERBOSE
	printf("\t[ ] Base address of allocated memory: %x\n", progMemory);
#endif

	// Load sections from the sections table into memory
	// TODO: work out the remaining size of the buffer
	memcpy_s(progMemory, sizeOfHeaders, data, sizeOfHeaders);
	for (int i = 0; i < numberOfSections; i++) {
		DWORD virtualAddress = sectionHeaders[i]->VirtualAddress;
		DWORD pointerToRawData = sectionHeaders[i]->PointerToRawData;
		DWORD sizeOfRawData = sectionHeaders[i]->SizeOfRawData;
		memcpy_s(progMemory + virtualAddress, sizeOfRawData, data + pointerToRawData, sizeOfRawData);
	}

	// Perform relocations if needed
	if ((DWORD)progMemory != imageBase) {
#ifdef L_VERBOSE
		printf("\t[ ] Relocating addresses\n");
#endif
		DWORD offset = (DWORD)progMemory - imageBase; // get the offset
#ifdef L_VERBOSE
		printf("\t[ ] Offset from preferred base address: %X\n", offset);
#endif
		DWORD relocSize = OPT_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size; // remaining size of the .reloc section (this value decreases as we parse each relocation table)
		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(progMemory + OPT_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); // pointer to the start of the relocation section

		// parse the .reloc section
		while (relocSize > 0) {
			DWORD virtualAddress = relocBlock->VirtualAddress;
			DWORD sizeOfBlock = relocBlock->SizeOfBlock;
			uint16_t * entry = (uint16_t *)((uint8_t *)relocBlock + 8);
			for (int i = 0; i < (sizeOfBlock - 8) / 2; i++) {
				// some ugly maths to get a pointer to where the address we need to fix is 
				DWORD * addr = ((DWORD *)(progMemory + relocBlock->VirtualAddress + (*entry % (1 << 12))));
				if (*entry >> 12 == IMAGE_REL_BASED_HIGHLOW) { // only fix the addresses where the type is 3
					*addr = *addr + offset; // fix the address
					entry++; // go to the next entry
				}
			}
			// update the remaining size and get the next block
			relocSize -= sizeOfBlock;
			relocBlock = (PIMAGE_BASE_RELOCATION)((uint8_t *)relocBlock + sizeOfBlock);
		}
	}

	// Handle the imports in the imports table
	PIMAGE_IMPORT_DESCRIPTOR importDLL = (PIMAGE_IMPORT_DESCRIPTOR)(progMemory + OPT_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); // nasty pointer math to get first import descriptor
#ifdef L_VERBOSE
	printf("\t[ ] Address of import table: %X\n", importDLL);
#endif
	while (importDLL->Characteristics != 0) { // make sure we haven't reached the end of the import section
#ifdef L_VERBOSE
		printf("\t[ ] Handling import from: %s\n", (char *)(progMemory + importDLL->Name));
#endif
		HMODULE currentDLL = LoadLibraryA((char *)(progMemory + importDLL->Name));
		PIMAGE_THUNK_DATA importThunk = (PIMAGE_THUNK_DATA)(progMemory + importDLL->OriginalFirstThunk); // first thunk that points to import data
		PIMAGE_THUNK_DATA importAddr = (PIMAGE_THUNK_DATA)(progMemory + importDLL->FirstThunk); // first thunk that points to where we need to fix the address
		while (importThunk->u1.AddressOfData != 0) { // make sure there's more to import from the current DLL
			FARPROC procAddr = NULL;
			// try importing the function
			if (importThunk->u1.AddressOfData >> 31 == 0) { // we can use the function name to import
			// thank you stack overflow: https://stackoverflow.com/questions/41581363/how-we-can-get-hint-in-image-import-by-name-struct-in-pe-file
				PIMAGE_IMPORT_BY_NAME importInfo = (PIMAGE_IMPORT_BY_NAME)(progMemory + importThunk->u1.AddressOfData);
#ifdef L_VERBOSE
				printf("\t[ ] Importing function by name: %s\n", importInfo->Name);
#endif
				procAddr = GetProcAddress(currentDLL, importInfo->Name);
			} else { // we need to import by ordinal
				PIMAGE_IMPORT_BY_NAME importInfo = (PIMAGE_IMPORT_BY_NAME)((BYTE *)importThunk);
#ifdef L_VERBOSE
				printf("\t[ ] Importing function by ordinal: %X\n", importInfo->Name);
#endif
				procAddr = GetProcAddress(currentDLL, importInfo->Hint);
			}
			// check that the import succeeded
			if (procAddr == NULL) {
				printf("\t[-] Failed to load a function from the DLL\n");
				return FALSE;
			} else {
#ifdef L_VERBOSE
				printf("\t[ ] Function address: %x\n", procAddr);
#endif
				importAddr->u1.Function = procAddr;
			}
			// parse the next original thunk and increment to the next thunk we need to modify
			importThunk = (PIMAGE_THUNK_DATA)((BYTE *)importThunk + sizeof(IMAGE_THUNK_DATA));
			importAddr = (PIMAGE_THUNK_DATA)((BYTE *)importAddr + sizeof(IMAGE_THUNK_DATA));
		}
		// get the info of the next DLL we need to load functions from
		importDLL = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)importDLL + sizeof(IMAGE_IMPORT_DESCRIPTOR)); // NEVER EVER EVER USE sizeof(PIMAGE_...) - using that here caused a good couple days worth of grief
	}

	// Change permissions on the .text section to make it executable
	for (int i = 0; i < numberOfSections; i++) {
		if (strcmp(sectionHeaders[i]->Name, ".text") == 0) {
			DWORD trash; // because VirtualProtect requires that we provide this
			if (!VirtualProtect(progMemory + sectionHeaders[i]->VirtualAddress, sectionHeaders[i]->Misc.VirtualSize, PAGE_EXECUTE_READ, &trash)) {
				printf("\t[-] Failed to make .text section executable\n");
				return FALSE;
			}
		}
	}

	// Jump to entry point of the program
#ifdef L_VERBOSE
	printf("\t[ ] Relative address of entry point: %x\n", OPT_header->AddressOfEntryPoint);
#endif
	uint8_t * addrEntryPoint = OPT_header->AddressOfEntryPoint + progMemory;
	((int * (*)())addrEntryPoint)(); // ugly type cast, but it gets the job done

	// free any dynamically allocated memory
#ifdef L_VERBOSE
	printf("\t[ ] Freeing dynamically allocated memory\n");
#endif
	VirtualFree(progMemory, 0, MEM_RELEASE);
	free(sectionHeaders);

	return TRUE;
}