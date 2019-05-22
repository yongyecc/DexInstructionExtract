package struct;

public class MethodIdsItem {
	
	public short class_idx;
	public short proto_idx;
	public int name_idx;
	
	public static int getSize(){
		return 2 + 2 + 4;
	}
	
}
