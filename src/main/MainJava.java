package main;


public class MainJava {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		/**
		 * 需要删除的临时变量
		 */
		String fp = "C:\\Users\\xiongchaochao\\Desktop\\classes.dex";
//		if(args.length < 1) {
//			System.out.printf("\n\tjava -jar readdex.jar <dex file>\n");
//			System.exit(0);
//		}
//		String fp = args[0];
		int ftype;
		ftype = Utils.getFileType(fp);
		switch (ftype) {
		//file type：APK
		case 0:
			
			break;
		//file type：dex
		case 1:
			byte[] bt = Utils.getData(fp);
			Utils.extraInstructions(bt, "a");
			break;
		default:
			
			break;
		}	
	}	
}
