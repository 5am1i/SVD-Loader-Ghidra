# Load specified SVD and generate peripheral memory maps & structures.
#@author Thomas Roth <thomas.roth@leveldown.de>, Ryan Pavlik <ryan.pavlik@gmail.com>
#@keybinding 
#@menupath 
#@toolbar


# More information:
# https://leveldown.de/blog/svd-loader/
# License: GPLv3
# -*- coding: utf-8 -*-

import sys

from cmsis_svd.parser import SVDParser
from ghidra.program.model.data import Structure, StructureDataType, UnsignedIntegerDataType, DataTypeConflictHandler
from ghidra.program.model.data import UnsignedShortDataType, ByteDataType, UnsignedLongLongDataType
from ghidra.program.model.mem import MemoryBlockType
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import MemoryConflictException

class MemoryRegion:
	def __init__(self, name, start, end, name_parts=None):
		self.start = start
		self.end = end
		if name_parts:
			self.name_parts = name_parts
		else:
			self.name_parts = [name]

		assert(self.start < self.end)

	@property
	def name(self):
		return "_".join(self.name_parts)

	def length(self):
		return self.end - self.start

	def __lt__(self, other):
		return self.start < other.start

	def combine_with(self, other):
		return MemoryRegion(None,
			min(self.start, other.start),
			max(self.end, other.end),
			self.name_parts + other.name_parts)

	def combine_from(self, other):
		self.start = min(self.start, other.start)
		self.end = max(self.end, other.end)
		self.name_parts.extend(other.name_parts)
	
	def overlaps(self, other):
		if other.end < self.start:
			return False
		if self.end < other.start:
			return False
		return True
	
	def __str__(self):
		return "{}({}:{})".format(self.name, hex(self.start), hex(self.end))

def reduce_memory_regions(regions):
	regions.sort()
	print("Original regions: " + ", ".join(str(x) for x in regions))
	result = [regions[0]]
	for region in regions[1:]:
		if region.overlaps(result[-1]):
			result[-1].combine_from(region)
		else:
			result.append(region)

	print("Reduced regions: " + ", ".join(str(x) for x in result))
	return result

def calculate_peripheral_size(peripheral, default_register_size):
	size = 0
	for register in peripheral.registers:
		register_size = default_register_size if not register._size else register._size
		# If register_size is still None, use default value 32 bits (4 bytes)
		if register_size is None:
			register_size = 32
		size = max(size, register.address_offset + register_size/8)
	
	# Add reasonable limits to prevent excessive memory usage
	# Most peripherals should be much smaller than 64KB
	max_reasonable_size = 65536  # 64KB
	if size > max_reasonable_size:
		print("\t\tWarning: Calculated size {} bytes is very large, limiting to {} bytes".format(size, max_reasonable_size))
		size = max_reasonable_size
	
	return size


svd_file = askFile("Choose SVD file", "Load SVD File")

print("Loading SVD file...")
parser = SVDParser.for_xml_file(str(svd_file))
print("\tDone!")

# Clean up existing memory map and data structures
print("Cleaning up existing memory map...")
try:
	# Get all memory blocks and remove SVD-related ones
	memory_blocks = currentProgram.memory.getBlocks()
	cleared_blocks = 0
	
	print("\tFound {} memory blocks to check".format(len(memory_blocks)))
	
	for block in memory_blocks:
		block_name = block.getName()
		block_name_lower = block_name.lower()
		
		# Check if this block should be removed
		should_remove = False
		
		# Check for SVD-related keywords
		svd_keywords = ['svd', 'peripheral', 'mmio', 'registers', 'icb', 'nvic', 'syst', 'scb', 'mpu', 'sau', 'dcb', 'sig', 'fpe', 'cm', 'dib']
		if any(keyword in block_name_lower for keyword in svd_keywords):
			should_remove = True
		
		# Also check for blocks that contain underscores (often from SVD loader)
		if '_' in block_name and len(block_name) > 10:
			should_remove = True
		
		# Check for blocks in peripheral address ranges
		block_start = block.getStart().getOffset()
		if 0x40000000 <= block_start <= 0x60000000 or 0xE0000000 <= block_start <= 0xE0100000:
			should_remove = True
		
		if should_remove:
			try:
				print("\tRemoving memory block: {} (start: {}, end: {})".format(
					block_name, hex(block.getStart().getOffset()), hex(block.getEnd().getOffset())))
				# Use a simpler approach without MemoryConflictHandler
				currentProgram.memory.removeBlock(block, ghidra.util.task.TaskMonitor.DUMMY)
				cleared_blocks += 1
			except Exception as e:
				print("\t\tFailed to remove block {}: {}".format(block_name, str(e)))
		else:
			print("\tKeeping memory block: {} (start: {}, end: {})".format(
				block_name, hex(block.getStart().getOffset()), hex(block.getEnd().getOffset())))
	
	# Clear existing data structures in peripheral address ranges
	# This is a more aggressive cleanup - clear data in common peripheral address ranges
	peripheral_ranges = [
		(0x40000000, 0x60000000),  # Common peripheral range for ARM Cortex-M
		(0xE0000000, 0xE0100000),  # System control and debug range
	]
	
	cleared_data_count = 0
	for start_addr, end_addr in peripheral_ranges:
		start = currentProgram.memory.getAddress(start_addr)
		end = currentProgram.memory.getAddress(end_addr)
		if start and end:
			# Clear data in this range with more aggressive approach
			try:
				# First try to clear code units
				cleared = listing.clearCodeUnits(start, end, False)
				if cleared > 0:
					cleared_data_count += cleared
				
				# Also try to clear any remaining data at specific addresses
				current_addr = start
				while current_addr.compareTo(end) <= 0:
					data_at_addr = listing.getDataAt(current_addr)
					if data_at_addr is not None:
						try:
							listing.clearCodeUnits(current_addr, current_addr, False)
							cleared_data_count += 1
						except:
							pass
					current_addr = current_addr.add(1)
			except Exception as e:
				print("\t\tWarning: Failed to clear data in range {}:{} - {}".format(hex(start_addr), hex(end_addr), str(e)))
	
	# Clear existing data types that might be from previous SVD loads
	dtm = currentProgram.getDataTypeManager()
	data_types = dtm.getAllDataTypes()
	cleared_types = 0
	
	for data_type in data_types:
		type_name = data_type.getName().lower()
		# Clear structure types that look like peripherals
		if (isinstance(data_type, StructureDataType) and 
			any(keyword in type_name for keyword in ['peripheral', 'register', 'mmio', 'icb', 'nvic', 'syst', 'scb', 'mpu', 'sau', 'dcb', 'sig', 'fpe', 'cm', 'dib'])):
			try:
				dtm.remove(data_type, DataTypeConflictHandler.REPLACE_HANDLER)
				cleared_types += 1
			except:
				pass  # Ignore errors when removing types
	
	# Additional cleanup: Force clear any remaining data in specific problematic ranges
	problematic_ranges = [
		(0xE000ED00, 0xE000ED90),  # SCB range that was causing issues
		(0xE000EDD0, 0xE000EDF0),  # SAU range
		(0xE000EDF0, 0xE000EE00),  # DCB range
		(0xE000EF50, 0xE000EF80),  # CM range
		(0xE000E000, 0xE000E200),  # Broader NVIC/SYST range
	]
	
	additional_cleared = 0
	for start_addr, end_addr in problematic_ranges:
		start = currentProgram.memory.getAddress(start_addr)
		end = currentProgram.memory.getAddress(end_addr)
		if start and end:
			try:
				# Multiple aggressive cleanup methods
				print("\tAggressively clearing range {}:{}".format(hex(start_addr), hex(end_addr)))
				
				# Method 1: Clear code units
				cleared = listing.clearCodeUnits(start, end, False)
				if cleared > 0:
					additional_cleared += cleared
					print("\t\tCleared {} code units".format(cleared))
				
				# Method 2: Clear data at each address individually
				current_addr = start
				individual_cleared = 0
				while current_addr.compareTo(end) <= 0:
					try:
						data_at_addr = listing.getDataAt(current_addr)
						if data_at_addr is not None:
							listing.clearCodeUnits(current_addr, current_addr, False)
							individual_cleared += 1
					except:
						pass
					current_addr = current_addr.add(1)
				
				if individual_cleared > 0:
					additional_cleared += individual_cleared
					print("\t\tIndividually cleared {} data units".format(individual_cleared))
				
				# Method 3: Try to clear any remaining instructions
				try:
					inst_cleared = listing.clearCodeUnits(start, end, True)  # Clear instructions too
					if inst_cleared > 0:
						additional_cleared += inst_cleared
						print("\t\tCleared {} instructions".format(inst_cleared))
				except:
					pass
					
			except Exception as e:
				print("\t\tWarning: Failed to aggressively clear range {}:{} - {}".format(hex(start_addr), hex(end_addr), str(e)))
	
	# Force cleanup: Remove all memory blocks that might be from previous SVD loads
	print("\tPerforming force cleanup of memory blocks...")
	force_cleared = 0
	
	# Get fresh list of memory blocks after initial cleanup
	remaining_blocks = currentProgram.memory.getBlocks()
	for block in remaining_blocks:
		block_name = block.getName()
		block_start = block.getStart().getOffset()
		
		# Force remove blocks in peripheral ranges regardless of name
		if (0x40000000 <= block_start <= 0x60000000 or 
			0xE0000000 <= block_start <= 0xE0100000):
			try:
				print("\tForce removing memory block: {} (start: {}, end: {})".format(
					block_name, hex(block_start), hex(block.getEnd().getOffset())))
				# Use a simpler approach without MemoryConflictHandler
				currentProgram.memory.removeBlock(block, ghidra.util.task.TaskMonitor.DUMMY)
				force_cleared += 1
			except Exception as e:
				print("\t\tFailed to force remove block {}: {}".format(block_name, str(e)))
	
	if cleared_blocks > 0 or cleared_data_count > 0 or cleared_types > 0 or additional_cleared > 0 or force_cleared > 0:
		print("\tCleared {} memory blocks, {} data units, {} data types, {} additional data units, and {} force-cleared blocks".format(
			cleared_blocks, cleared_data_count, cleared_types, additional_cleared, force_cleared))
	else:
		print("\tNo existing SVD-related memory structures found to clear")
		
except Exception as e:
	print("\tWarning: Failed to clean up existing memory map: " + str(e))

# CM0, CM4, etc
cpu_type = parser.get_device().cpu.name
# little/big
cpu_endian = parser.get_device().cpu.endian

default_register_size = parser.get_device().size

# Not all SVDs contain these fields
if cpu_type and not cpu_type.startswith("CM"):
	print("Currently only Cortex-M CPUs are supported, so this might not work...")
	print("Supplied CPU type was: " + cpu_type)

if cpu_endian and cpu_endian != "little":
	print("Currently only little endian CPUs are supported.")
	print("Supplied CPU endian was: " + cpu_endian)
	sys.exit(1)

# Get things we need
listing = currentProgram.getListing()
symtbl = currentProgram.getSymbolTable()
dtm = currentProgram.getDataTypeManager()
space = currentProgram.getAddressFactory().getDefaultAddressSpace()

namespace = symtbl.getNamespace("Peripherals", None)
if not namespace:
	namespace = currentProgram.getSymbolTable().createNameSpace(None, "Peripherals", SourceType.ANALYSIS)

peripherals = parser.get_device().peripherals

print("Generating memory regions...")
# First, we need to generate a list of memory regions.
# This is because some SVD files have overlapping peripherals...
memory_regions = []
for peripheral in peripherals:
	start = peripheral.base_address
	length = peripheral.address_block.offset + peripheral.address_block.size
	end = peripheral.base_address + length

	memory_regions.append(MemoryRegion(peripheral.name, start, end))
memory_regions = reduce_memory_regions(memory_regions)

print("Generating memory blocks...")
# Create memory blocks:
for r in memory_regions:
	print("\t" + str(r))
	try:
		addr = space.getAddress(r.start)
		length = r.length()

		# Check if memory block already exists at this address
		existing_block = currentProgram.memory.getBlock(addr)
		if existing_block is not None:
			print("\tMemory block already exists at address " + hex(r.start) + ", skipping...")
			continue

		t = currentProgram.memory.createUninitializedBlock(r.name, addr, length, False)
		t.setRead(True)
		t.setWrite(True)
		t.setExecute(False)
		t.setVolatile(True)
		t.setComment("Generated by SVD-Loader.")
	except ghidra.program.model.mem.MemoryConflictException as e:
		print("\tFailed to generate due to conflict in memory block for: " + r.name)
		print("\t", e)
	except Exception as e:
		print("\tFailed to generate memory block for: " + r.name)
		print("\t", e)

print("\tDone!")

print("Generating peripherals...")
for peripheral in peripherals:
	print("\t" + peripheral.name)

	if(len(peripheral.registers) == 0):
		print("\t\tNo registers.")
		continue

	try:
		# Iterate registers to get size of peripheral
		# Most SVDs have an address-block that specifies the size, but
		# they are often far too large, leading to issues with overlaps.
		length = calculate_peripheral_size(peripheral, default_register_size)

		# Generate structure for the peripheral
		peripheral_struct = StructureDataType(peripheral.name, length)

		peripheral_start = peripheral.base_address
		peripheral_end = peripheral_start + length
		print("\t\t{}:{}".format(hex(peripheral_start), hex(peripheral_end)))

		# Sort registers by address offset to ensure proper placement order
		sorted_registers = sorted(peripheral.registers, key=lambda r: r.address_offset)

		for register in sorted_registers:
			register_size = default_register_size if not register._size else register._size
			# If register_size is still None, use default value 32 bits (4 bytes)
			if register_size is None:
				register_size = 32

			r_type = UnsignedIntegerDataType()
			rs = register_size / 8
			if rs == 1:
				r_type = ByteDataType()
			elif rs == 2:
				r_type = UnsignedShortDataType()
			elif rs == 8:
				r_type = UnsignedLongLongDataType()

			print("\t\t\t{}({}:{})".format(register.name, hex(register.address_offset), hex(register.address_offset + register_size/8)))
			
			# Ensure there's enough space before placing the register
			current_size = peripheral_struct.getLength()
			required_size = register.address_offset + register_size/8
			if required_size > current_size:
				# Add undefined bytes to fill the gap
				peripheral_struct.growStructure(required_size - current_size)
			
			peripheral_struct.replaceAtOffset(register.address_offset, r_type, register_size/8, register.name, register.description)

		addr = space.getAddress(peripheral_start)

		dtm.addDataType(peripheral_struct, DataTypeConflictHandler.REPLACE_HANDLER)
		symtbl.createLabel(addr,
						peripheral.name,
						namespace,
						SourceType.USER_DEFINED)
		
		# Check if the structure size is reasonable and within memory bounds
		struct_length = peripheral_struct.getLength()
		if struct_length > 65536:  # 64KB limit
			print("\t\tStructure size {} bytes is too large, skipping peripheral {}".format(struct_length, peripheral.name))
			continue
		
		# Check if the target address range is within valid memory bounds
		end_addr = addr.add(struct_length - 1)
		
		# Check if addresses are within memory space
		if not currentProgram.memory.contains(addr):
			print("\t\tStart address {} is outside valid memory bounds, skipping peripheral {}".format(
				hex(peripheral_start), peripheral.name))
			continue
			
		if not currentProgram.memory.contains(end_addr):
			print("\t\tEnd address {} is outside valid memory bounds, skipping peripheral {}".format(
				hex(peripheral_start + struct_length - 1), peripheral.name))
			continue
		
		# Check if there's a memory block at the target address
		start_block = currentProgram.memory.getBlock(addr)
		end_block = currentProgram.memory.getBlock(end_addr)
		
		if start_block is None:
			print("\t\tNo memory block exists at start address {}, skipping peripheral {}".format(
				hex(peripheral_start), peripheral.name))
			continue
			
		if end_block is None or start_block != end_block:
			print("\t\tAddress range {}:{} spans multiple or no memory blocks, skipping peripheral {}".format(
				hex(peripheral_start), hex(peripheral_start + struct_length - 1), peripheral.name))
			continue
		
		# Aggressive pre-creation cleanup
		print("\t\tPerforming aggressive cleanup before creating data structure...")
		
		# Method 1: Clear the entire range
		try:
			cleared = listing.clearCodeUnits(addr, end_addr, False)
			if cleared > 0:
				print("\t\t\tCleared {} code units in range".format(cleared))
		except Exception as e:
			print("\t\t\tWarning: Failed to clear range - {}".format(str(e)))
		
		# Method 2: Clear each address individually
		individual_cleared = 0
		current_addr = addr
		while current_addr.compareTo(end_addr) <= 0:
			try:
				data_at_addr = listing.getDataAt(current_addr)
				if data_at_addr is not None:
					listing.clearCodeUnits(current_addr, current_addr, False)
					individual_cleared += 1
			except:
				pass
			current_addr = current_addr.add(1)
		
		if individual_cleared > 0:
			print("\t\t\tIndividually cleared {} data units".format(individual_cleared))
		
		# Method 3: Clear any instructions in the range
		try:
			inst_cleared = listing.clearCodeUnits(addr, end_addr, True)
			if inst_cleared > 0:
				print("\t\t\tCleared {} instructions".format(inst_cleared))
		except:
			pass
		
		# Method 4: Force clear any remaining data
		try:
			# Try to clear any remaining data structures
			current_addr = addr
			while current_addr.compareTo(end_addr) <= 0:
				try:
					# Check for any remaining data
					data_at_addr = listing.getDataAt(current_addr)
					if data_at_addr is not None:
						# Try to remove the data
						listing.clearCodeUnits(current_addr, current_addr, False)
				except:
					pass
				current_addr = current_addr.add(1)
		except:
			pass
		
		# Now try to create the data structure
		print("\t\tCreating data structure...")
		listing.createData(addr, peripheral_struct, False)
		
	except Exception as e:
		print("\t\tFailed to generate peripheral " + peripheral.name)
		print("\t\tError: " + str(e))
