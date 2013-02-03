#include <linux/module.h>   // Needed by all modules
#include <linux/kernel.h>   // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros
#include <linux/mm.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <asm-x86/mman.h>
#include <asm-x86/uaccess.h>
#include <asm-x86/processor.h>
#include <asm-x86/errno.h>

#include "defines.h"	// Descriptions of PE Header

#define USER_ADDR_TOP	(0xC0000000)
#define BAD_ADDR(x)	((unsigned long)(x) > USER_ADDR_TOP)

static int load_pe_binary(struct linux_binprm *bprm, struct pt_regs *regs);
static int load_pe_library(struct file *file);
static int pe_core_dump(long signr, struct pt_regs *regs, struct file *file);

static struct linux_binfmt pe_format;

static unsigned int pe_map(struct file *pfile, unsigned int addr, unsigned int len, int prot, int flag, unsigned int offset)
{
	unsigned int map_addr;
	int retval;

	printk("do_mmap! addr = %#x, offset = %#x, length = %#x\n", addr, offset, len);

	//down_write(&current->mm->mmap_sem);
	if (PAGEOFFSET(offset)) // offset must be aligned with pagesize, required by do_mmap
	{
		printk("offset is invalid for do_mmap! manual reading!\n");
		
		prot |= PROT_WRITE;	// no recovering yet >_<
		map_addr = do_mmap(NULL, addr, len, prot, flag, 0);	// anonymous mapping
		
		printk("map_addr: %#x\n", map_addr);

		char* ptmp = (char*)kmalloc(len, GFP_KERNEL);	
	    if (!ptmp)
	    {
		    printk("Failed to kmalloc loading PE file!\n");
		    return 0;
	    }
	    printk("ptmp: %#x\n", ptmp);


		//retval = vfs_read(pfile, map_addr, len, &pos);
		kernel_read(pfile, offset, ptmp, len);
		retval = copy_to_user(map_addr, ptmp, len);
		if (retval != 0)
		{
			printk("copy_to_user failed! retval = %d\n", retval);
			return -ENOMEM;
		}
		else
			printk("copy_to_user is done! first char: %x\n", *(unsigned char*)map_addr);

		kfree(ptmp);
	}
	else
	{
		printk("offset is valid for do_mmap!\n", retval);
		map_addr = do_mmap(pfile, addr, len, prot, flag, offset);
		printk("map_addr: %#x\n", map_addr);
		printk("do_mmap is done! first char: %x\n", *(unsigned char*)map_addr);
	}
	//up_write(&current->mm->mmap_sem);

	return map_addr;
}

static void pe_set_brk(unsigned long start, unsigned long end)
{
	start = PAGESTART(start);
	end = PAGEALIGN(end);
	if (end <= start)
		return;
	do_brk(start, end - start);
}

static void pe_padzero(unsigned int start_bss)
{
	unsigned int nbyte;

	nbyte = start_bss & (PAGE_SIZE - 1);
	if (nbyte) 
	{
		nbyte = PAGE_SIZE - nbyte;
		clear_user((void*)start_bss, nbyte);
	}
}

static int load_dll(struct file* file, unsigned int* map_addr, unsigned int* export_table_useraddr, unsigned int* length, unsigned int* rva_export, unsigned int* rva_base)
{
	IMAGE_DOS_HEADER *pe_dos_header = NULL;
	IMAGE_NT_HEADER *pe_nt_header = NULL;
	IMAGE_FILE_HEADER *pe_file_header = NULL;
	IMAGE_OPTIONAL_HEADER *pe_optional_header = NULL;
	IMAGE_DATA_DIRECTORY *pe_data_directory = NULL;
	IMAGE_SECTION_HEADER *pe_section_header = NULL, *pe_ppnt = NULL;
	unsigned int image_base;
	unsigned int export_table_base;
	unsigned int addr;
	int pe_prot = 0, pe_flags;
	int i;
	int retval = 0;

	printk("\nload_dll: %s\n", file->f_dentry->d_name.name);

	// Load IMAGE_DOS_HEADER
	pe_dos_header = (IMAGE_DOS_HEADER*)kmalloc(sizeof(IMAGE_DOS_HEADER), GFP_KERNEL);	
	if (!pe_dos_header)
	{
		retval = -ENOMEM;
		printk("Failed to kmalloc for pe_dos_header!\n");
		goto out;
	}
	retval = kernel_read(file, 0, (char*)pe_dos_header, sizeof(IMAGE_DOS_HEADER));
	if (retval < 0)
		goto err_read_dos_header;

	// Is it a PE executive file?
	if (pe_dos_header->e_magic != 0x5a4d || !pe_dos_header->e_lfanew)
	{
		printk("NOT DLL 1\n");
		goto err_not_pe;
	}
	// Read in all of the header information
	pe_nt_header = (IMAGE_NT_HEADER*)kmalloc(sizeof(IMAGE_NT_HEADER), GFP_KERNEL);
	if (!pe_nt_header)
	{
		retval = -ENOMEM;
		printk("Failed to kmalloc for pe_nt_header!\n");
		goto out;
	}
	retval = kernel_read(file, pe_dos_header->e_lfanew, (char*)pe_nt_header, sizeof(IMAGE_NT_HEADER));
	if (retval < 0)
		goto err_read_nt_header;
	pe_file_header = &pe_nt_header->FileHeader;
	pe_optional_header = &pe_nt_header->OptionalHeader;
	if (pe_nt_header->Signature != 0x00004550 || !(pe_file_header->Characteristics & IMAGE_FILE_DLL))
	{
		printk("NOT DLL 2\n");
		goto err_not_pe;
	}

	printk("DLL!!!\n");

	image_base = pe_optional_header->ImageBase;

	if (pe_file_header->NumberOfSections > 0)
	{
		pe_section_header = (IMAGE_SECTION_HEADER*)kmalloc(sizeof(IMAGE_SECTION_HEADER) * pe_file_header->NumberOfSections, GFP_KERNEL);
		if (!pe_section_header)
		{
			retval = -ENOMEM;
			printk("Failed to kmalloc for pe_section_header!\n");
			goto out;
		}
		retval = kernel_read(file, pe_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADER), (char*)pe_section_header, sizeof(IMAGE_SECTION_HEADER) * pe_file_header->NumberOfSections);
		if (retval < 0)
			goto err_read_section_header;

		// Map the whole image
		pe_flags = MAP_PRIVATE|MAP_DENYWRITE|MAP_EXECUTABLE;
		pe_prot = PROT_READ|PROT_WRITE|PROT_EXEC;
		addr = pe_map(file, image_base, pe_optional_header->SizeOfImage, pe_prot, pe_flags, pe_optional_header->SizeOfHeaders);
		printk("pe_map retval: %#x\n", addr);
		if (BAD_ADDR(addr) || addr == 0)
			goto err_bad_addr;
		if (addr != image_base)
		{
			// RELOCATE THE DLL!!!
			printk("This dll needs to be relocated!\n");
		}
		*map_addr = addr;

		// Map each section
		for (i = 0, pe_ppnt = pe_section_header; i < pe_file_header->NumberOfSections; i++, pe_ppnt++)
		{
			unsigned int v_addr = pe_ppnt->VirtualAddress + addr;
			loff_t pos = pe_ppnt->PointerToRawData;

			printk("map the section %d! addr = %#x, offfset = %x, len = %x\n", i, v_addr, pe_ppnt->PointerToRawData, pe_ppnt->SizeOfRawData);
			retval = file->f_op->read(file, v_addr, pe_ppnt->SizeOfRawData, &pos);
			if (retval < 0)
			{
				printk("file_read failed! retval = %d\n", retval);
				goto err_file_read;
			}
		}

		// Deal with the export table
		*rva_export = pe_optional_header->DataDirectory[0].VirtualAddress;
		*rva_base = 0;
		printk("RVA of export table: %#x\n", *rva_export);

		for (i = 0, pe_ppnt = pe_section_header; i < pe_file_header->NumberOfSections; i++, pe_ppnt++)
		{
			unsigned int v_addr = pe_ppnt->VirtualAddress;
			loff_t pos = pe_ppnt->PointerToRawData;
			if (*rva_export >= v_addr && *rva_export - v_addr < PAGE_SIZE)
			{
				*rva_base = v_addr;
				printk("RVA of section containing export table: %#x\n", *rva_base);
				*length = pe_ppnt->SizeOfRawData;
				printk("max length of export table: %x\n", *length);
				break;
			}
		}
		if (!length)
			goto err_no_export;

		*export_table_useraddr = *rva_base + addr;
	}
	
	// outdoors
out:
	if (pe_nt_header)
		kfree(pe_nt_header);
	if (pe_section_header)
		kfree(pe_section_header);
	return retval;

err_not_pe:
	retval = -ENOEXEC;
	printk("err_not_pe! retval: %d\n", retval);
	goto out;
err_read_dos_header:
	printk("err_read_dos_header! retval: %d\n", retval);
	goto out;
err_read_nt_header:
	printk("err_read_nt_header! retval: %d\n", retval);
	goto out;
err_read_section_header:
	printk("err_read_section_header! retval: %d\n", retval);
	goto out;
err_flush:
	printk("err_flush! retval: %d\n", retval);
	goto out;
err_bad_addr:
	printk("err_addr! addr: %#x\n", addr);
	retval = -ENOMEM;
	goto out;
err_no_export:
	retval = -EINVAL;
	printk("err_no_export!\n");
	goto out;
err_file_read:
	retval = -EIO;
	printk("err_file_read!\n");
	goto out;
}

static unsigned int resolve_import(char* dll_name, char* func_name)
{
	static char* last_dll = NULL;
	char dll_path[MAX_DLL_PATH_LEN] = "/usr/dlls/";
	int i, retval;
	unsigned int func_addr = 0;
	struct file *file = NULL;
	unsigned int export_table_base = 0;
	static unsigned int dll_map_addr = 0;
	static unsigned int export_table_useraddr = 0;
	static unsigned int length_of_export = 0;
	static unsigned int rva_export, rva_base;
	
	printk("=======resolve_import starts\n");
	printk("dll name: %s; func name: %s\n", dll_name, func_name);
	for (i = 0; i < strlen(dll_name) && i < MAX_DLL_PATH_LEN - 11; i++)
	{
		dll_path[10 + i] = dll_name[i];
	}
	printk("dll path: %s\n", dll_path);

	if (last_dll == dll_name)
	{
		printk("old dll!\n");
	}
	else
	{
		printk("new dll!\n");
		last_dll = dll_name;

		file = filp_open(dll_path, O_RDONLY, 0);
		if (IS_ERR(file))
		{
			printk("failed to open the file: %s\n", dll_path);
		  	return 0;
		}
		printk("succeeded to open the file: %s\n", dll_path);
		
		retval = load_dll(file, &dll_map_addr, &export_table_useraddr, &length_of_export, &rva_export, &rva_base);
		if (retval < 0)
		{
			printk("load_pe_library failed! retval = %d\n", retval);
			filp_close(file, 0);
			return 0;
		}
		if (!export_table_useraddr || !length_of_export)
		{
			printk("didn't find export_table!\n");
			filp_close(file, 0);
			return 0;
		}
	}
		
	export_table_base = kmalloc(length_of_export, GFP_KERNEL);
	if (!export_table_base)
	{
		printk("failed to kmalloc for export_table!\n");
		filp_close(file, 0);
		return 0;
	}
	copy_from_user(export_table_base, export_table_useraddr, length_of_export);
	IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(export_table_base + (rva_export - rva_base));
	unsigned int func_num = export_directory->NumberOfFunctions;
	unsigned int rva_name = export_directory->AddressOfNames;
	unsigned int rva_addr = export_directory->AddressOfFunctions - rva_base + export_table_base;
	char* name;

	for (i = 0; i < func_num; i++)
	{
		name = (char*)(*(unsigned int*)(export_table_base + (rva_name - rva_base))) - rva_base + export_table_base;
		if (strcmp(name, func_name) == 0)
		{
			func_addr = *(unsigned int*)rva_addr + dll_map_addr;
			printk("%s func_addr = %#x\n", name, func_addr);
			break;
		}
		rva_name += sizeof(unsigned int);
		rva_addr += sizeof(unsigned int);
	}

	if (file)
		filp_close(file, 0);
	if (export_table_base)
		kfree(export_table_base);

	printk("=======resolve_import returns\n");
	return func_addr;
}

static int load_pe_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	IMAGE_DOS_HEADER *pe_dos_header = NULL;
	IMAGE_NT_HEADER *pe_nt_header = NULL;
	IMAGE_FILE_HEADER *pe_file_header = NULL;
	IMAGE_OPTIONAL_HEADER *pe_optional_header = NULL;
	IMAGE_DATA_DIRECTORY *pe_data_directory = NULL;
	IMAGE_SECTION_HEADER *pe_section_header = NULL, *pe_ppnt = NULL;
	IMAGE_IMPORT_DESCRIPTOR *pe_import_descriptor = NULL;
	int i;
	int retval = 0;
	unsigned int error;
	unsigned int pe_entry;
	unsigned int image_base;
	unsigned int start_code, end_code, start_data, end_data, start_bss, end_bss;
	unsigned int import_table_base;
 
	printk("\nload_pe_binary: %s\n", bprm->filename);
	
	// Load IMAGE_DOS_HEADER
	pe_dos_header = (IMAGE_DOS_HEADER*)bprm->buf;	

	// Is it a PE executive file?
	if (pe_dos_header->e_magic != 0x5a4d || !pe_dos_header->e_lfanew)
	{
		printk("NOT PE 1\n");
		goto err_not_pe;
	}
	// Read in all of the header information
	pe_nt_header = (IMAGE_NT_HEADER*)kmalloc(sizeof(IMAGE_NT_HEADER), GFP_KERNEL);
	if (!pe_nt_header)
	{
		retval = -ENOMEM;
		printk("failed to kmalloc for pe_nt_header!\n");
		goto out;
	}
	retval = kernel_read(bprm->file, pe_dos_header->e_lfanew, (char*)pe_nt_header, sizeof(IMAGE_NT_HEADER));
	if (retval < 0)
		goto err_read_nt_header;
	pe_file_header = &pe_nt_header->FileHeader;
	pe_optional_header = &pe_nt_header->OptionalHeader;
	if (pe_nt_header->Signature != 0x00004550 ||
		!(pe_file_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) || 
		pe_file_header->Characteristics & IMAGE_FILE_DLL)
	{
		printk("NOT PE 2\n");
		goto err_not_pe;
	}

	printk("PE!!!\n");

	// Flush all traces of the currently running executable
	retval = flush_old_exec(bprm);
	if (retval)
	{
		goto err_flush;
	}

	set_personality(PER_LINUX);

	start_bss = 0;
	end_bss = 0;
	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;
	image_base = pe_optional_header->ImageBase;

	retval = setup_arg_pages(bprm, WIN32_STACK_LIMIT + WIN32_LOWEST_ADDR, EXSTACK_DISABLE_X);
	printk("bprm->p = %#x\n", bprm->p);
	if (retval < 0) 
	{
		send_sig(SIGKILL, current, 0);
		printk("failed to setup_arg_pages! retval: %d\n", retval);
		goto out;
	}
	current->mm->start_stack = bprm->p;

	// Load sections into memory
	printk("ImageBase: %#x\n", image_base);
	printk("NumberOfSections: %d\n", pe_file_header->NumberOfSections);
	if (pe_file_header->NumberOfSections > 0)
	{
		pe_section_header = (IMAGE_SECTION_HEADER*)kmalloc(sizeof(IMAGE_SECTION_HEADER) * pe_file_header->NumberOfSections, GFP_KERNEL);
		if (!pe_section_header)
		{
			retval = -ENOMEM;
			printk("failed to kmalloc for pe_section_header!\n");
			goto out;
		}
		retval = kernel_read(bprm->file, pe_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADER), (char*)pe_section_header, sizeof(IMAGE_SECTION_HEADER) * pe_file_header->NumberOfSections);
		if (retval < 0)
			goto err_read_section_header;

		for (i = 0, pe_ppnt = pe_section_header; i < pe_file_header->NumberOfSections; i++, pe_ppnt++)
		{
			int pe_prot = 0, pe_flags;
			unsigned int v_addr;
			printk(">>>Loading section %d: %s\n", i + 1, pe_ppnt->Name);
			
			if (pe_ppnt->Characteristics & IMAGE_SCN_MEM_READ) {pe_prot |= PROT_READ; printk("PROT_READ "); }
			if (pe_ppnt->Characteristics & IMAGE_SCN_MEM_WRITE) {pe_prot |= PROT_WRITE; printk("PROT_WRITE "); }
			if (pe_ppnt->Characteristics & IMAGE_SCN_MEM_EXECUTE) {pe_prot |= PROT_EXEC; printk("PROT_EXEC"); }
			printk("\n");
			pe_flags = MAP_PRIVATE|MAP_DENYWRITE|MAP_EXECUTABLE;
			// We assume that there are no sections to be loaded dynamically
			pe_flags |= MAP_FIXED;
			v_addr = pe_ppnt->VirtualAddress;
			error = pe_map(bprm->file, image_base + v_addr, pe_ppnt->SizeOfRawData, pe_prot, pe_flags, pe_ppnt->PointerToRawData);
			printk("pe_map retval: %#x\n", error);
			if (BAD_ADDR(error) || error == 0)
				continue;
			if (pe_ppnt->Characteristics & IMAGE_SCN_CNT_CODE)
			{
				// code
				printk("This section contains code\n");
				if (start_code > v_addr) start_code = v_addr;
				if (end_code < v_addr + pe_ppnt->SizeOfRawData) end_code = v_addr + pe_ppnt->SizeOfRawData;
			}
			else if (pe_ppnt->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				// data
				printk("This section contains data\n");
				if (start_data > v_addr || !start_data) start_data = v_addr;
				if (end_data < v_addr + pe_ppnt->SizeOfRawData) end_data = v_addr + pe_ppnt->SizeOfRawData;
			}
			else if (pe_ppnt->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				// bss
				printk("This section contains bss\n");
				if (start_bss < v_addr) start_bss = v_addr;
				if (end_bss < v_addr + pe_ppnt->Misc.VirtualSize) end_bss = v_addr + pe_ppnt->Misc.VirtualSize;
			}
		}
	}
	
	pe_entry = pe_optional_header->AddressOfEntryPoint + image_base;
	start_bss += image_base;
	end_bss += image_base;
	start_code += image_base;
	end_code += image_base;
	end_code += 0x200;
	start_data += image_base;
	end_data += image_base;
	printk("------->\nentry: %#x\n", pe_entry);
	set_binfmt(&pe_format);
	compute_creds(bprm);
	
	current->flags &= ~PF_FORKNOEXEC;
	current->mm->start_code = start_code;
	current->mm->end_code = end_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_brk = start_bss;
	current->mm->brk = end_bss;

	printk("start_code: %#x, end_code: %#x\n", current->mm->start_code, current->mm->end_code);
	printk("start_data: %#x, end_data: %#x\n", current->mm->start_data, current->mm->end_data);
	printk("start_bss: %#x, end_bss: %#x\n", current->mm->start_brk, current->mm->brk);
	printk("start_stack: %#x\n", current->mm->start_stack);
		
	if (start_bss > image_base && end_bss > image_base && start_bss <= end_bss)
	{
		printk("set_brk with value 0\n");
		pe_set_brk(start_bss, end_bss);
		pe_padzero(start_bss);
	}

	// Deal with the import table
	unsigned int length = 0;
	unsigned int rva_import = pe_optional_header->DataDirectory[1].VirtualAddress;
	unsigned int rva_base = 0;
	printk("RVA of import table: %#x\n", rva_import);
	
	for (i = 0, pe_ppnt = pe_section_header; i < pe_file_header->NumberOfSections; i++, pe_ppnt++)
	{
			unsigned int v_addr = pe_ppnt->VirtualAddress;
			if (rva_import >= v_addr && rva_import - v_addr <= PAGE_SIZE)
			{
				rva_base = v_addr;
				printk("RVA of section containing import table: %#x\n", rva_base);
				length = pe_ppnt->SizeOfRawData;
				printk("max length of import table: %x\n", length);
				break;
			}
	}
	if (!length)
		goto err_no_import;
	
	import_table_base = kmalloc(length, GFP_KERNEL);
	if (!import_table_base)
	{
		retval = -ENOMEM;
		printk("failed to kmalloc for import_table!\n");
		goto out;
	}
	copy_from_user(import_table_base, rva_base + image_base, length);

	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(import_table_base + (rva_import - rva_base));
	IMAGE_THUNK_DATA* image_thunk_data = NULL;
	unsigned int func_addr;

	while (import_descriptor->Name != 0)
	{
		printk("------->\nRVA of import_descriptor: %x\n", (unsigned int)import_descriptor - import_table_base);
		//printk("RVA of DLL Name: %x\n", import_descriptor->Name - rva_base);
		printk("DLL name: %s\n", (char*)(import_descriptor->Name - rva_base + import_table_base));
		image_thunk_data = (IMAGE_THUNK_DATA*)(import_descriptor->FirstThunk - rva_base + import_table_base);
		while (image_thunk_data->u1.AddressOfData != 0)
		{
			printk("resolving function %s...\n", ((IMAGE_IMPORT_BY_NAME*)(image_thunk_data->u1.AddressOfData - rva_base + import_table_base))->Name);
			
			func_addr = resolve_import((char*)(import_descriptor->Name - rva_base + import_table_base),((IMAGE_IMPORT_BY_NAME*)(image_thunk_data->u1.AddressOfData - rva_base + import_table_base))->Name);
			if (!func_addr)
			{
				printk("failed to resolve the function %s at %s\n", ((IMAGE_IMPORT_BY_NAME*)(image_thunk_data->u1.AddressOfData - rva_base + import_table_base))->Name, (char*)(import_descriptor->Name - rva_base + import_table_base)); 
				goto err_linking_failed;
			}
			printk("%s address: %#x\n", ((IMAGE_IMPORT_BY_NAME*)(image_thunk_data->u1.AddressOfData - rva_base + import_table_base))->Name, func_addr);
			// Rewrite the import_address_table
			image_thunk_data->u1.Function = func_addr;
			
			image_thunk_data = (unsigned int)image_thunk_data + sizeof(IMAGE_THUNK_DATA);
		}
		import_descriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	copy_to_user(rva_base + image_base, import_table_base, length);
	
	start_thread(regs, pe_entry, bprm->p);
	printk("\n>>start_thread!<<\n");

	retval = 0;
	
	// outdoors
out:
	if (pe_nt_header)
		kfree(pe_nt_header);
	if (pe_section_header)
		kfree(pe_section_header);
	if (pe_import_descriptor)
		kfree(pe_import_descriptor);
	return retval;

err_not_pe:
	retval = -ENOEXEC;
	printk("err_not_pe! retval: %d\n", retval);
	goto out;
err_read_nt_header:
	printk("err_read_nt_header! retval: %d\n", retval);
	goto out;
err_read_section_header:
	printk("err_read_section_header! retval: %d\n", retval);
	goto out;
err_flush:
	printk("err_flush! retval: %d\n", retval);
	goto out;
err_no_import:
	retval = -EINVAL;
	printk("err_no_import!\n");
	goto out;
err_linking_failed:
	retval = -EINVAL;
	printk("err_linking_failed!\n");
	goto out;

}

static int load_pe_library(struct file *f)
{
	printk("load_pe_library:\n");
	return -ENOEXEC;
}

static int pe_core_dump(long signr, struct pt_regs *regs, struct file *file)
{
	printk("pe_core_dump\n");
	return -ENOEXEC;
}

static int winux_init(void)
{
	printk("++++++++++++++++++++\n");
	pe_format.module = THIS_MODULE;
	pe_format.load_binary = load_pe_binary;
	pe_format.load_shlib = load_pe_library;
	pe_format.core_dump = pe_core_dump;
	pe_format.min_coredump = PAGE_SIZE;
	pe_format.hasvdso = 0;
	register_binfmt(&pe_format);
	return 0;
}

static void winux_exit(void)
{
	unregister_binfmt(&pe_format);
	printk("--------------------\n");
}

module_init(winux_init);
module_exit(winux_exit);

MODULE_LICENSE("GPL");

