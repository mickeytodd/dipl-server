import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class Server {

	public static void main(String[] args) throws Exception {
		Thread t = new Thread() {
			Hashtable<String, String> hash = new Hashtable<String, String>();
			
			byte[] keyBytes = "mihailot".getBytes("ASCII");
			DESKeySpec keySpec = new DESKeySpec(keyBytes);
	        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
	        SecretKey key = factory.generateSecret(keySpec);
	        
	        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	        
			@Override
			public void run() {
				try {
					ServerSocket ss = new ServerSocket(2000);
					Socket sk = ss.accept();
					BufferedReader cin = new BufferedReader (new InputStreamReader(sk.getInputStream()));
					PrintStream cout = new PrintStream (sk.getOutputStream());
					
					String username, password;
					
					hash.put("mickey@mickey","passshello:)");
			
					username = cin.readLine();
							
					//Enumeration names;
					//String key;
					//names = hash.keys();
					//   while(names.hasMoreElements()) {
					//      key = (String) names.nextElement();
					//      System.out.println("Key: " +key+ " & Value: " +
					//      hash.get(key));
					//   }
						
					System.out.print("Client: "+username+"\n");
					if (hash.containsKey(username)) {
						cout.println("OK");
						System.out.print("Server: OK\n");
						password = cin.readLine();
						System.out.print("Client[encrypted]: "+password+"\n");
						byte[] pass = password.getBytes("UTF-8");
						password = new String(pass);
						
						String time = new SimpleDateFormat("yyMMddHHmm").format(new Date());
						System.out.print("Time: "+time+"\n");
						byte[] zero = new byte [] {0, 0, 0, 0, 0, 0, 0, 0};
						IvParameterSpec iv = new IvParameterSpec (zero);
						desCipher.init(Cipher.DECRYPT_MODE, key, iv);
						byte[] tr = Base64.getDecoder().decode(pass);
						byte[] textEncrypted = desCipher.doFinal(tr);
						
						password = new String (textEncrypted, "UTF-8");
						System.out.print("Server: Received password is "+password+"\n");
						
						int timeminus1 = Integer.parseInt(time);
						if (timeminus1%100 != 0)
							timeminus1--;
						else {
							timeminus1 -= 7641;
							if ((timeminus1-2359)%1000000 == 0) {
								int x = 1600000000;	//ovo vazi samo za 2016.
								int mil = 1000000;
								if (timeminus1-mil == x)
									timeminus1 -= 88690000;
								if ((timeminus1-2*mil == x) || (timeminus1-4*mil ==x) || (timeminus1-6*mil == x) 
								|| (timeminus1-8*mil == x) || (timeminus1-9*mil == x) || (timeminus1-11*mil == x))
									timeminus1 -= 690000;
								if ((timeminus1-5*mil == x) || (timeminus1-7*mil == x) || (timeminus1-10*mil == x)
								|| (timeminus1-12*mil == x))
									timeminus1 -= 700000;
								else {
									timeminus1 -= 710000;
								}
							}
								
						}
						String time1 = "" + timeminus1;
						while (time1.length() < 10)
							time1 = "0"+time1;
						int timeplus1 = Integer.parseInt(time);
						if (timeplus1%59 != 0)
							timeplus1++;
						else
							timeplus1 += 41;
						String time2 = "" + timeplus1;
						while (time2.length() < 10)
							time2 = "0"+time2;
						String s = hash.get(username) + time;
						String s1 = hash.get(username) + time1;
						String s2 = hash.get(username) + time2;
						if (password.equals(s) || password.equals(s1) || password.equals(s2)) {
							cout.println("Logged in");
							System.out.print("Server: Logged in\n");
						}
						else {
							cout.println("Not OK");
							System.out.print("Server: Wrong password, real is "+s+" or "+s1+" or "+s2+"\n");
						}
					}
					else {
						cout.println("Not OK");
						System.out.print("Server: "+username+" not found!");
					}
					//ss.close();
					//sk.close();
					//cin.close();
					//cout.close();
				} catch (Exception e) {
				e.printStackTrace();
				}
			}
		};
		t.start();
	}
}