package main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Adler32;

import struct.ClassCodeItem;
import struct.ClassDataItem;
import struct.ClassDefItem;
import struct.EncodedField;
import struct.EncodedMethod;
import struct.HeaderType;
import struct.MethodIdsItem;
import struct.StringIdsItem;
import struct.TypeIdsItem;
import struct.TypeItem;
import struct.TypeListItem;

public class Utils {
	
	public static int FT_APK = 0;
	public static int FT_DEX = 1;
	
	private static int flag = 0;
	private static byte[] dexByte = null;
	private static String dir_path;
	private static int stringIdsSize = 0;
	private static int stringIdOffset = 0;
	private static int typeIdsSize = 0;
	private static int typeIdsOffset = 0;
	private static int classIdsSize = 0;
	private static int classIdsOffset = 0;
	private static int methodIdsSize = 0;
	private static int methodIdsOffset = 0;
	private static List<StringIdsItem> stringIdsList = new ArrayList<StringIdsItem>();
	private static List<ClassDefItem> classIdsList = new ArrayList<ClassDefItem>(); 
	private static List<String> stringList = new ArrayList<String>();
	private static List<MethodIdsItem> methodIdsList = new ArrayList<MethodIdsItem>();
	private static List<TypeIdsItem> typeIdsList = new ArrayList<TypeIdsItem>();

	/**
	 * 读取文件头magic来判断文件类型
	 * 
	 * @param filePath 需要检测文件的路径
	 * @return	返回代表不同文件类型的int值
	 */
	public static int getFileType(String filePath) {
		int ft;
		byte[] bt = new byte[4];
		String fMagic;
		dir_path = filePath.substring(0, filePath.lastIndexOf("\\"))+"\\";
		try {
			FileInputStream fileInputStream = new FileInputStream(filePath);
			fileInputStream.read(bt, 0, 4);
			fMagic = new String(bt);
			if(fMagic.startsWith("PK"))
				return FT_APK;
			if(fMagic.startsWith("dex"))
				return FT_DEX;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return FT_DEX;
	}
	
	/**
	 * 根据参数类名，我们将该类的所有方法内部的指令置空来隐藏源代码。
	 * 
	 * @param dexFileStream	dex文件的字节流
	 * @param className	需要置空内部方法的类
	 */
	public static void extraInstructions(byte[] dexFileStream, String className) {
		//遍历class段
		parseDexHeader(dexFileStream);
		parseStringIds(dexFileStream);
		parseStringList(dexFileStream);
		parseTypeIds(dexFileStream);
		parseMethodIds(dexFileStream);
		parseClassIds(dexFileStream);
		resetDexCheckSum(dexByte);
		File dFile = new File(dir_path + "dump.dex");
		try {
			dFile.createNewFile();
			FileOutputStream mFileOutputStream = new FileOutputStream(dFile);
			mFileOutputStream.write(dexByte);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.printf("\t\t    dump dex file to %s\n", dir_path + "dump.dex");
		
	}
	
	/**
	 * 根据传递的byte流dex文件数据，解析dex文件头，并打印出来
	 * 
	 * @param byteSrc	被解析的dex文件的字节流数据
	 */
	public static void parseDexHeader(byte[] byteSrc){
		HeaderType headerType = new HeaderType();
		//magic：8字节
		byte[] magic = Utils.copyByte(byteSrc, 0, 8);
		headerType.magic = magic;
		
		//checksum：4字节
		byte[] checksumByte = Utils.copyByte(byteSrc, 8, 4);
		String checksum_hex = Utils.reverseOrderHexStr(Utils.bytesToHexString(checksumByte));
		headerType.checksum = Utils.bytesToHexString(checksumByte) + "(" + checksum_hex + "h)";
		
		//signature：20字节
		byte[] siganature = Utils.copyByte(byteSrc, 12, 20);
		headerType.siganature = siganature;
		
		//file_size：4字节
		byte[] fileSizeByte = Utils.copyByte(byteSrc, 32, 4);
		headerType.file_size = Utils.byte2int(fileSizeByte);
		
		//header_size：4字节
		byte[] headerSizeByte = Utils.copyByte(byteSrc, 36, 4);
		headerType.header_size = Utils.byte2int(headerSizeByte);
		
		//endian_tag：4字节
		byte[] endianTagByte = Utils.copyByte(byteSrc, 40, 4);
		String endian_tag_hexstr = Utils.reverseOrderHexStr(Utils.bytesToHexString(endianTagByte));
		headerType.endian_tag = Utils.bytesToHexString(endianTagByte) + "(" + endian_tag_hexstr + "h)";
		
		//静态链接link_size： 4字节
		byte[] linkSizeByte = Utils.copyByte(byteSrc, 44, 4);
		headerType.link_size = Utils.byte2int(linkSizeByte);
		
		//link_off： 4字节
		byte[] linkOffByte = Utils.copyByte(byteSrc, 48, 4);
		headerType.link_off = Utils.byte2int(linkOffByte);
		
		//文件开头到 data 区段的偏移量,map_off： 4字节
		byte[] mapOffByte = Utils.copyByte(byteSrc, 52, 4);
		headerType.map_off = Utils.byte2int(mapOffByte);
		
		//string_ids_size: 
		byte[] stringIdsSizeByte = Utils.copyByte(byteSrc, 56, 4);
		headerType.string_ids_size = Utils.byte2int(stringIdsSizeByte);
		
		//string_ids_off
		byte[] stringIdsOffByte = Utils.copyByte(byteSrc, 60, 4);
		headerType.string_ids_off = Utils.byte2int(stringIdsOffByte);
		
		//所有类型：type_ids_size
		byte[] typeIdsSizeByte = Utils.copyByte(byteSrc, 64, 4);
		headerType.type_ids_size = Utils.byte2int(typeIdsSizeByte);
		
		//type_ids_off
		byte[] typeIdsOffByte = Utils.copyByte(byteSrc, 68, 4);
		headerType.type_ids_off = Utils.byte2int(typeIdsOffByte);
		
		//方法原型proto_ids_size
		byte[] protoIdsSizeByte = Utils.copyByte(byteSrc, 72, 4);
		headerType.proto_ids_size = Utils.byte2int(protoIdsSizeByte);
		
		//proto_ids_off
		byte[] protoIdsOffByte = Utils.copyByte(byteSrc, 76, 4);
		headerType.proto_ids_off = Utils.byte2int(protoIdsOffByte);
		
		//field_ids_size
		byte[] fieldIdsSizeByte = Utils.copyByte(byteSrc, 80, 4);
		headerType.field_ids_size = Utils.byte2int(fieldIdsSizeByte);
		
		//field_ids_off
		byte[] fieldIdsOffByte = Utils.copyByte(byteSrc, 84, 4);
		headerType.field_ids_off = Utils.byte2int(fieldIdsOffByte);
		
		//method_ids_size
		byte[] methodIdsSizeByte = Utils.copyByte(byteSrc, 88, 4);
		headerType.method_ids_size = Utils.byte2int(methodIdsSizeByte);
		
		//method_ids_off
		byte[] methodIdsOffByte = Utils.copyByte(byteSrc, 92, 4);
		headerType.method_ids_off = Utils.byte2int(methodIdsOffByte);
		
		//每个类的各种信息class_defs_size
		byte[] classDefsSizeByte = Utils.copyByte(byteSrc, 96, 4);
		headerType.class_defs_size = Utils.byte2int(classDefsSizeByte);
		
		//class_defs_off
		byte[] classDefsOffByte = Utils.copyByte(byteSrc, 100, 4);
		headerType.class_defs_off = Utils.byte2int(classDefsOffByte);
		
		//data_size
		byte[] dataSizeByte = Utils.copyByte(byteSrc, 104, 4);
		headerType.data_size = Utils.byte2int(dataSizeByte);
		
		//data_off
		byte[] dataOffByte = Utils.copyByte(byteSrc, 108, 4);
		headerType.data_off = Utils.byte2int(dataOffByte);
		
		stringIdsSize = headerType.string_ids_size;
		stringIdOffset = headerType.string_ids_off;
		typeIdsSize = headerType.type_ids_size;
		typeIdsOffset = headerType.type_ids_off;
		classIdsSize = headerType.class_defs_size;
		classIdsOffset = headerType.class_defs_off;
		methodIdsSize = headerType.method_ids_size;
		methodIdsOffset = headerType.method_ids_off;
	}
	

	/**
	 * 解析出每个类的每个方法,这个区段的方法信息由结构体 DexMethodId 存储，主要包含以下三个属性：
	 * 	1. classIdx：方法所在类(指向DexTypeId列表的索引)
	 * 	2. protoIdx：方法原型(指向DexProtoId列表的索引)
	 *  3. nameIdx：方法名(指向DexStringId列表的索引)
	 * 
	 * 然后将解析的内容打印出来
	 * 
	 * @param srcByte	被解析的dex文件的字节流数据
	 */
	public static void parseMethodIds(byte[] srcByte){
		int idSize = MethodIdsItem.getSize();
		int countIds = methodIdsSize;
//		System.out.println("Total " + String.valueOf(countIds) + " methods(类方法)\n");
		for(int i=0;i<countIds;i++){
			MethodIdsItem item = new MethodIdsItem();
			byte[] methodItemByte =  Utils.copyByte(srcByte, methodIdsOffset+i*idSize, idSize);
			byte[] classIdxByte = Utils.copyByte(methodItemByte, 0, 2);
			item.class_idx = Utils.byte2Short(classIdxByte);
			byte[] protoIdxByte = Utils.copyByte(methodItemByte, 2, 2);
			item.proto_idx = Utils.byte2Short(protoIdxByte);
			byte[] nameIdxByte = Utils.copyByte(methodItemByte, 4, 4);
			item.name_idx = Utils.byte2int(nameIdxByte);
			methodIdsList.add(item);
		}
//		int i=0;
//		for(MethodIdsItem item : methodIdsList){
//			int classIndex = typeIdsList.get(item.class_idx).descriptor_idx;
//			int returnIndex = protoIdsList.get(item.proto_idx).return_type_idx;
//			String returnTypeStr = stringList.get(typeIdsList.get(returnIndex).descriptor_idx);
//			int shortIndex = protoIdsList.get(item.proto_idx).shorty_idx;
//			String shortStr = stringList.get(shortIndex);
//			List<String> paramList = protoIdsList.get(item.proto_idx).parametersList;
//			StringBuilder parameters = new StringBuilder();
//			parameters.append(returnTypeStr+"(");
//			for(String str : paramList){
//				parameters.append(str+",");
//			}
//			parameters.append(")");
//			System.out.println("Method_id[" + String.valueOf(i) + "]\t-->\t"
//					+ String.valueOf(item.class_idx) + "," + String.valueOf(item.proto_idx) + "," + String.valueOf(item.name_idx) + "\t-->\t"
//					+ "Type_id[" + String.valueOf(item.class_idx) + "],Proto_id[" + String.valueOf(item.proto_idx) + "],String_id[" + String.valueOf(item.name_idx) + "]\t-->\t"
//					+ "class:"+stringList.get(classIndex)+"=>proto:"+parameters+"=>name:"+stringList.get(item.name_idx));
//			i++;
//		}
		
	}
	
	/**
	 * 解析dex文件格式中的stringids段，获取string_ids_item结构体，然后将解析的内容打印出来。
	 * StringIdsItem对象对应string_ids_item结构体，使用StringIdsItem列表将dex文件中所有string_ids_item结构体保存。
	 * string_ids_item结构体只存有StringDataItem结构体的偏移地址，具体数据存放在数据区域
	 * 
	 * @param byteSrc 被解析的dex文件的字节流数据
	 */
	public static void parseStringIds(byte[] byteSrc){
		byte[] idsByte;
		int idSize = StringIdsItem.getSize();
		int countIds = stringIdsSize;
//		System.out.println("Total " + String.valueOf(countIds) + " strings\n");
		for(int i=0;i<countIds;i++){
			StringIdsItem item = new StringIdsItem();
			idsByte = Utils.copyByte(byteSrc, stringIdOffset+i*idSize, idSize);
			item.string_data_off = Utils.byte2int(idsByte);
			stringIdsList.add(item);
		}
	}
	//解析StringDataItem结构体,获取里面的字符串数据,并打印出来
	public static void parseStringList(byte[] srcByte){
		int i=0;
		for(StringIdsItem item : stringIdsList){
			String str = Utils.getString(srcByte, item.string_data_off);
//			System.out.println("String_id[" + String.valueOf(i) + "]\t-->\t" + str);
			i++;
			stringList.add(str);
		}
	}
	
	/**
	 * 解析出dex文件中用到的所有类型的类名。
	 * 这个区段保存有DexTypeId结构体，这个结构体只有一个属性，是一个索引值，指向stringids段的字符串，然后将解析的内容打印出来
	 * 
	 * @param srcByte	被解析的dex文件的字节流数据
	 */
	public static void parseTypeIds(byte[] srcByte){
		int idSize = TypeIdsItem.getSize();
		int countIds = typeIdsSize;
//		System.out.println("Total " + String.valueOf(countIds) + " types\n");
		for(int i=0;i<countIds;i++){
			TypeIdsItem item = new TypeIdsItem();
			byte[] descriptorIdxByte = Utils.copyByte(Utils.copyByte(srcByte, typeIdsOffset+i*idSize, idSize), 0, 4);
			item.descriptor_idx = Utils.byte2int(descriptorIdxByte);
			typeIdsList.add(item);
		}
		int index = 0;
		for(TypeIdsItem item : typeIdsList){
//			System.out.println("Type_id[" + String.valueOf(index) + "]\t-->\t" +String.valueOf(item.descriptor_idx) + "\t-->\tString_id[" + 
//		String.valueOf(item.descriptor_idx) + "]\t-->\t" + stringList.get(item.descriptor_idx));
			index++;
		}
	}
	


	public static String getString(byte[] srcByte, int startOff){
		byte size = srcByte[startOff];
		byte[] strByte = Utils.copyByte(srcByte, startOff+1, size);
		String result = "";
		try{
			result = new String(strByte, "UTF-8");
		}catch(Exception e){
		}
		return result;
	}

	public static String reverseOrderHexStr(String hexstr) {
		String[] hexs = hexstr.split(" ");
		int len = hexs.length;
		String result = "";
		for(int i=hexs.length; i>0; i--) {
			int index = i - 1;
			result = result + hexs[index];
		}
		return result;
	}


	public static byte[] copyByte(byte[] src, int start, int len){
		if(src == null){
			return null;
		}
		if(start > src.length){
			return null;
		}
		if((start+len) > src.length){
			return null;
		}
		if(start<0){
			return null;
		}
		if(len<=0){
			return null;
		}
		byte[] resultByte = new byte[len];
		for(int i=0;i<len;i++){
			resultByte[i] = src[i+start];
		}
		return resultByte;
	}
	
	/**
	 * 将dex文件字节流中指定位置的字节数据修改为0
	 * 
	 * @param src	dex文件的字节流
	 * @param start	需要修改的数据的起始位置
	 * @param len	需要修改的长度
	 * @return	返回修改后的dex文件字节流
	 */
	public static byte[] set_instru2null(byte[] src, int start, int len) {
		if(src == null){
			return null;
		}
		if(start > src.length){
			return null;
		}
		if((start+len) > src.length){
			return null;
		}
		if(start<0){
			return null;
		}
		if(len<=0){
			return null;
		}
		byte[] resultByte = new byte[src.length];
		for(int i=0; i<src.length-1; i++) {
			if(i<start) {
				resultByte[i] = src[i];
			}else if((i-start) < len){
				resultByte[i] = 0;
			}else {
				resultByte[i] = src[i];
			}
		}
		return resultByte;
	}

	/**
	 * 解析出每个自定义类（不包含java、android的内置类，如：int、string、android.app.Activity等）的详细信息，这个区段的每个类的详细信息由结构体 ClassDefItem 组成，
	 * 主要包含以下属性：
	 * 	1. classIdx：类名，指向DexTypeId列表的索引 
	 *  2. accessFlags：访问标志，具体参考ClassDefItem内部参数
	 *  3. superclassIdx：父类类名，指向DexTypeId列表的索引 
	 *  4. interfacesOff：接口，指向DexTypeList结构体的偏移
	 *  5. sourceFileIdx：源代码文件信息，指向DexStringId列表的索引。如果此项缺失，则用0xFFFFFFFF表示NO_INDEX
	 *  6. annotationsOff：注解，指向DexAnnotationsDirectoryItem结构体的偏移
	 *  7. classDataOff：类的字段、方法的信息，指向DexClassData结构体的偏移 
	 * 	8. staticValuesOff：指向data区段的DexEncodedArray结构体的偏移
	 * 
	 * @param srcByte	被解析的dex文件的字节流数据
	 */
	public static void parseClassIds(byte[] srcByte){
		int idSize = ClassDefItem.getSize();
		int countIds = classIdsSize;
//		System.out.println("Total " + String.valueOf(countIds) + " classes(自定义类)\n");
		for(int i=0;i<countIds;i++){
			ClassDefItem item = new ClassDefItem();
			byte[] classItemByte = Utils.copyByte(srcByte, classIdsOffset+i*idSize, idSize);
			byte[] classIdxByte = Utils.copyByte(classItemByte, 0, 4);
			item.class_idx = Utils.byte2int(classIdxByte);
			byte[] accessFlagsByte = Utils.copyByte(classItemByte, 4, 4);
			item.access_flags = Utils.byte2int(accessFlagsByte);
			byte[] superClassIdxByte = Utils.copyByte(classItemByte, 8, 4);
			item.superclass_idx = Utils.byte2int(superClassIdxByte);
			byte[] iterfacesOffByte = Utils.copyByte(classItemByte, 12, 4);
			item.iterfaces_off = Utils.byte2int(iterfacesOffByte);
			byte[] sourceFileIdxByte = Utils.copyByte(classItemByte, 16, 4);
			item.source_file_idx = Utils.byte2int(sourceFileIdxByte);
			byte[] annotationsOffByte = Utils.copyByte(classItemByte, 20, 4);
			item.annotations_off = Utils.byte2int(annotationsOffByte);
			byte[] classDataOffByte = Utils.copyByte(classItemByte, 24, 4);
			item.class_data_off = Utils.byte2int(classDataOffByte);
			byte[] staticValueOffByte = Utils.copyByte(classItemByte, 28, 4);
			item.static_value_off = Utils.byte2int(staticValueOffByte);
			classIdsList.add(item);
		}
		int index = 0;
		for(ClassDefItem item : classIdsList){
			//classid
//			System.out.printf("Class #%d\n", index);
			int classIdx = item.class_idx;
			TypeIdsItem typeItem = typeIdsList.get(classIdx);
			String classIdxString = stringList.get(typeItem.descriptor_idx);
			System.out.printf("\tClass descriptor:%s\n", classIdxString);
			//access fla
//			System.out.printf("\tAccess flags\t:0x%x\n", item.access_flags);
			//superclass id
			int superClassIdx = item.superclass_idx;
			TypeIdsItem superTypeItem = typeIdsList.get(superClassIdx);
			String superTypeString = stringList.get(superTypeItem.descriptor_idx);
//			System.out.printf("\tSuperClass\t:%s\n", superTypeString);
			//Interfaces
//			System.out.printf("\tInterfaces\t-\n");
			if(item.iterfaces_off != 0) {
				TypeListItem mTypeListItem = new TypeListItem();
				mTypeListItem.typeItemCount = Utils.byte2int(Utils.copyByte(srcByte, item.iterfaces_off, 4));
				byte[] typeListItemByte = Utils.copyByte(srcByte, item.iterfaces_off, 4+mTypeListItem.typeItemCount*2);
				for(int i=0; i<mTypeListItem.typeItemCount; i++) {
					TypeItem mTypeItem = new TypeItem();
					mTypeItem.typeidIndex = Utils.byte2Short(Utils.copyByte(typeListItemByte, 4+i*2, 2));
					mTypeListItem.typeitemList.add(mTypeItem);
				}
				
			}
			index++;
			if(item.class_data_off == 0) {
				continue;
			}
			parseClassDataItem(srcByte, item);
			System.out.printf("\n");
		}	
	}
	//解析class
	public static void parseClassDataItem(byte[] srcByte, ClassDefItem mClassDefItem){
			int dataOffset = mClassDefItem.class_data_off;
			ClassDataItem item = new ClassDataItem();
			for(int i=0;i<4;i++){
				byte[] byteAry = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += byteAry.length;
				int size = Utils.decodeUleb128(byteAry);
				if(i == 0){
					item.static_fields_size = size;
				}else if(i == 1){
					item.instance_fields_size = size;
				}else if(i == 2){
					item.direct_methods_size = size;
				}else if(i == 3){
					item.virtual_methods_size = size;
				}
			}
			//staticFields
			EncodedField[] staticFieldAry = new EncodedField[item.static_fields_size];
			for(int i=0;i<item.static_fields_size;i++){
				/**
				 *  public int filed_idx_diff;
					public int access_flags;
				 */
				EncodedField staticField = new EncodedField();
				staticField.filed_idx_diff = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += staticField.filed_idx_diff.length;
				staticField.access_flags = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += staticField.access_flags.length;
				staticFieldAry[i] = staticField;
			}
			//instanceFields
			EncodedField[] instanceFieldAry = new EncodedField[item.instance_fields_size];
			for(int i=0;i<item.instance_fields_size;i++){
				/**
				 *  public int filed_idx_diff;
					public int access_flags;
				 */
				EncodedField instanceField = new EncodedField();
				instanceField.filed_idx_diff = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += instanceField.filed_idx_diff.length;
				instanceField.access_flags = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += instanceField.access_flags.length;
				instanceFieldAry[i] = instanceField;
			}
			//directMethods
			EncodedMethod[] staticMethodsAry = new EncodedMethod[item.direct_methods_size];
			for(int i=0;i<item.direct_methods_size;i++){
				/**
				 *  public byte[] method_idx_diff;
					public byte[] access_flags;
					public byte[] code_off;
				 */
				EncodedMethod directMethod = new EncodedMethod();
				directMethod.method_idx_diff = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += directMethod.method_idx_diff.length;
				directMethod.access_flags = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += directMethod.access_flags.length;
				directMethod.code_off = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += directMethod.code_off.length;
				staticMethodsAry[i] = directMethod;
			}
			//virtualMethods
			EncodedMethod[] instanceMethodsAry = new EncodedMethod[item.virtual_methods_size];
			for(int i=0;i<item.virtual_methods_size;i++){
				/**
				 *  public byte[] method_idx_diff;
					public byte[] access_flags;
					public byte[] code_off;
				 */
				EncodedMethod instanceMethod = new EncodedMethod();
				instanceMethod.method_idx_diff = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += instanceMethod.method_idx_diff.length;
				instanceMethod.access_flags = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += instanceMethod.access_flags.length;
				instanceMethod.code_off = Utils.readUnsignedLeb128(srcByte, dataOffset);
				dataOffset += instanceMethod.code_off.length;
				instanceMethodsAry[i] = instanceMethod;
			}
			item.static_fields = staticFieldAry;
			item.instance_fields = instanceFieldAry;
			item.direct_methods = staticMethodsAry;
			item.virtual_methods = instanceMethodsAry;
			//打印classDataItem结构体
//			System.out.printf("\tStatic fields\t-\n");
			if(item.static_fields.length != 0) {
				for(int i=0; i<item.static_fields.length; i++) {
					int fieldIndex = Utils.decodeUleb128(item.static_fields[i].filed_idx_diff);
					int accessflag = Utils.decodeUleb128(item.static_fields[i].access_flags);

				}
			}
			if(item.instance_fields.length != 0) {
				for(int i=0; i<item.instance_fields.length; i++) {
					int fieldIndex = Utils.decodeUleb128(item.instance_fields[i].filed_idx_diff);
					int accessflag = Utils.decodeUleb128(item.instance_fields[i].access_flags);
				}
			}
//			System.out.printf("\tDirect methods\t-\n");
			if(item.direct_methods.length != 0) {
				for(int i=0; i<item.direct_methods.length; i++) {
					int methodIndex = Utils.decodeUleb128(item.direct_methods[i].method_idx_diff);
					int accessflag = Utils.decodeUleb128(item.direct_methods[i].access_flags);
					int code_off = Utils.decodeUleb128(item.direct_methods[i].code_off);
					if(code_off == 0) {
						System.out.printf("\t\t    null code item");
						continue;
					}
					
					//解析code_item结构体
//					System.out.printf("\t\t  code\t-\n");
					byte[] codeItemByte = Utils.copyByte(srcByte, code_off, 16);
					ClassCodeItem mClassCodeItem = new ClassCodeItem();
					mClassCodeItem.registersSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 0, 2));
					mClassCodeItem.insSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 2, 2));
					mClassCodeItem.outsSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 4, 2));
					mClassCodeItem.triesSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 6, 2));
					mClassCodeItem.debugInfoOff = Utils.byte2int(Utils.copyByte(codeItemByte, 8, 4));
					mClassCodeItem.insnsSize = Utils.byte2int(Utils.copyByte(codeItemByte, 12, 4));
					byte[] instruction_byte = Utils.copyByte(srcByte, code_off+16, mClassCodeItem.insnsSize*2);
					for(int j=0; j<mClassCodeItem.insnsSize; j++) {
						mClassCodeItem.insns.add(Utils.byte2Short(Utils.copyByte(instruction_byte, 2*j, 2)));
					}
					System.out.printf("\t\t  name\t:%s\n", stringList.get(methodIdsList.get(methodIndex).name_idx));
					System.out.printf("\t\t    instructions:%s\n", mClassCodeItem.insns.toString());
					System.out.printf("\t\t    指令置空：\n");
					if(flag == 0) {
						dexByte = set_instru2null(srcByte, code_off+16, mClassCodeItem.insnsSize*2);
						byte[] null_instruction = Utils.copyByte(dexByte, code_off+16, mClassCodeItem.insnsSize*2);
						flag++;
					}else{
						dexByte = set_instru2null(dexByte, code_off+16, mClassCodeItem.insnsSize*2);
					}
					byte[] null_byte = Utils.copyByte(dexByte, code_off+16, mClassCodeItem.insnsSize*2);
					System.out.println("\t\t" + Utils.bytesToHexString(null_byte)+"\n");
				}
			}
//			System.out.printf("\tVirtual methods\t-\n");
			if(item.virtual_methods.length != 0) {
				for(int i=0; i<item.virtual_methods.length; i++) {
					int methodIndex = Utils.decodeUleb128(item.virtual_methods[i].method_idx_diff);
					int accessflag = Utils.decodeUleb128(item.virtual_methods[i].access_flags);
					int code_off = Utils.decodeUleb128(item.virtual_methods[i].code_off);
					if(code_off == 0) {
						System.out.printf("\t\t    null code item");
						continue;
					}
					
					//解析code_item结构体
//					System.out.printf("\t\t  code\t-\n");
					byte[] codeItemByte = Utils.copyByte(srcByte, code_off, 16);
					ClassCodeItem mClassCodeItem = new ClassCodeItem();
					mClassCodeItem.registersSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 0, 2));
					mClassCodeItem.insSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 2, 2));
					mClassCodeItem.outsSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 4, 2));
					mClassCodeItem.triesSize = Utils.byte2Short(Utils.copyByte(codeItemByte, 6, 2));
					mClassCodeItem.debugInfoOff = Utils.byte2int(Utils.copyByte(codeItemByte, 8, 4));
					mClassCodeItem.insnsSize = Utils.byte2int(Utils.copyByte(codeItemByte, 12, 4));
					byte[] instruction_byte = Utils.copyByte(srcByte, code_off+16, mClassCodeItem.insnsSize*2);
					for(int j=0; j<mClassCodeItem.insnsSize; j++) {
						mClassCodeItem.insns.add(Utils.byte2Short(Utils.copyByte(instruction_byte, 2*j, 2)));
					}
					System.out.printf("\t\t  name\t:%s\n", stringList.get(methodIdsList.get(methodIndex).name_idx));
					System.out.printf("\t\t    instructions:%s\n", mClassCodeItem.insns.toString());
					System.out.printf("\t\t    指令置空：\n");
					if(flag == 0) {
						dexByte = set_instru2null(srcByte, code_off+16, mClassCodeItem.insnsSize*2);
						flag++;
					}else{
						dexByte = set_instru2null(dexByte, code_off+16, mClassCodeItem.insnsSize*2);
					}
					byte[] null_byte = Utils.copyByte(dexByte, code_off+16, mClassCodeItem.insnsSize*2);
					System.out.println("\t\t" + Utils.bytesToHexString(null_byte)+"\n");
				}
			}
	}
	
	public static void resetDexCheckSum(byte[] src) {
		byte[] SHA1byte = new byte[src.length-33];
		System.arraycopy(src, 32, SHA1byte, 0, src.length-33);
		byte[] sha1 = getSHA1(SHA1byte);
		replaceByte(dexByte, 12, sha1);
		byte[] checkByte = checksum_bin(dexByte, 12);
		replaceByte(dexByte, 8, checkByte);
	}
	
	/**
	 * 用特定字节数组来替换字节流中指定位置的字节
	 * 
	 * @param src	被替换的字节流
	 * @param offset	被替换的初始位置
	 * @param repByte	用来替换的字节数组
	 */
	public static void replaceByte(byte[] src, int offset, byte[] repByte) {
		for(int i=0; i<repByte.length; i++) {
			src[offset+i] = repByte[i];
		}
	}
	//计算checksum 
	public static byte[] checksum_bin(byte[] data, int off) { 
	    int len = data.length - off; 
	    Adler32 adler32 = new Adler32(); 
	    adler32.reset(); 
	    adler32.update(data, off, len); 
	    long checksum = adler32.getValue(); 
	    byte[] checksumbs = new byte[]{ 
	            (byte) checksum, 
	            (byte) (checksum >> 8), 
	            (byte) (checksum >> 16), 
	            (byte) (checksum >> 24)}; 
	    return checksumbs; 
	}  
	
	public static byte[] getSHA1(byte[] bt) {
		MessageDigest mMessageDigest;
		byte[] messageDigest = null;
		try {
			mMessageDigest = MessageDigest.getInstance("SHA-1");
			mMessageDigest.update(bt);
			messageDigest = mMessageDigest.digest();
			 StringBuffer hexString = new StringBuffer();
			for (int i = 0; i < messageDigest.length; i++) {
	            String shaHex = Integer.toHexString(messageDigest[i] & 0xFF);
	            if (shaHex.length() < 2) {
	                hexString.append(0);
	            }
	            hexString.append(shaHex);
	        }
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return messageDigest;
	}

	public static int decodeUleb128(byte[] byteAry) {
	    int result = 0;
		
	    if(byteAry.length == 1){
	    	return byteAry[0];
	    }
	    if(byteAry.length == 2){
	        result = (byteAry[0] & 0x7f) | ((byteAry[1] & 0x7f) << 7);
	        return result;
	    }
	    if(byteAry.length == 3){
	        result = (byteAry[0] & 0x7f) | ((byteAry[1] & 0x7f) << 7) | ((byteAry[2] & 0x7f) << 14);
	        return result;
	    }
	    if(byteAry.length == 4){
	    	result = (byteAry[0] & 0x7f) | ((byteAry[1] & 0x7f) << 7) | ((byteAry[2] & 0x7f) << 14) | ((byteAry[3] & 0x7f) << 21);
	        return result;
	    }
        if(byteAry.length == 5){
        	result = (byteAry[0] & 0x7f) | ((byteAry[1] & 0x7f) << 7) | ((byteAry[2] & 0x7f) << 14) | ((byteAry[3] & 0x7f) << 21) | ((byteAry[4] & 0x7f) << 28);
            return result;
        }
        return result;
	}

	public static int byte2int(byte[] res) { 
		int targets = (res[0] & 0xff) | ((res[1] << 8) & 0xff00)
				| ((res[2] << 24) >>> 8) | (res[3] << 24); 
		return targets; 
	}

	public static short byte2Short(byte[] b) { 
        short s = 0; 
        short s0 = (short) (b[0] & 0xff);
        short s1 = (short) (b[1] & 0xff); 
        s1 <<= 8; 
        s = (short) (s0 | s1); 
        return s; 
    }

	public static byte[] readUnsignedLeb128(byte[] srcByte, int offset){
		List<Byte> byteAryList = new ArrayList<Byte>();
		byte bytes = Utils.copyByte(srcByte, offset, 1)[0];
		byte highBit = (byte)(bytes & 0x80);
		byteAryList.add(bytes);
		offset ++;
		while(highBit != 0){
			bytes = Utils.copyByte(srcByte, offset, 1)[0];
			highBit = (byte)(bytes & 0x80);
			offset ++;
			byteAryList.add(bytes);
		}
		byte[] byteAry = new byte[byteAryList.size()];
		for(int j=0;j<byteAryList.size();j++){
			byteAry[j] = byteAryList.get(j);
		}
		return byteAry;
	}
	
	public static String bytesToHexString(byte[] src){
		StringBuilder stringBuilder = new StringBuilder("");  
		if (src == null || src.length <= 0) {  
			return null;  
		}  
		for (int i = 0; i < src.length; i++) {  
			//限制在0-255范围内
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);  
			if (hv.length() < 2) {  
				stringBuilder.append(0);  
			}  
			stringBuilder.append(hv+" "); 
		}  
		return stringBuilder.toString();  
	} 
	
	/**
	 * 根据提供的文件路径返回，字节流数据
	 * 
	 * @param fp	需要转化成字节流的文件
	 * @param callback
	 */
	public static byte[] getData(String fp) {
		// TODO Auto-generated method stub
		byte[] bt = null;
		try {
			FileInputStream mFileInputStream = new FileInputStream(fp);
			//因为下面读取字节时会多读一位返回-1，所以多申请一个字节空间，防止越界异常
			bt = new byte[mFileInputStream.available()+1];
			int off = 0;
			while((mFileInputStream.read(bt, off, 1)) != -1) {
				off++;
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(bt.length != 0) {
			return bt;
		}else {
			
		}
		return null;
	}
}
