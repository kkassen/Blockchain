/*--------------------------------------------------------

1. Kyle Arick Kassen / Date: July 3, 2021 - July 12, 2021

2. Java version:

C:\Users\IQ1006\JavaPrograms\CSC435\Blockchain>java -version
openjdk version "11.0.4" 2019-07-16 LTS
OpenJDK Runtime Environment Corretto-11.0.4.11.1 (build 11.0.4+11-LTS)
OpenJDK 64-Bit Server VM Corretto-11.0.4.11.1 (build 11.0.4+11-LTS, mixed mode)

3. Compiling:
 • As per the assignment requirements—issue the following command twice:
    >javac -cp "gson-2.8.2.jar" Blockchain.java
    >javac -cp "gson-2.8.2.jar" Blockchain.java

4. Instructions and Details for Running the Program:
• Once complied [see above: #3]—
• Type the .bat file into the terminal command window:
>AllStart.bat
    • The .bat file contains the following:
        start java -cp ".;gson-2.8.2.jar" Blockchain 0
        start java -cp ".;gson-2.8.2.jar" Blockchain 1
        java -cp ".;gson-2.8.2.jar" Blockchain 2
*NOTE: running a single process will cause errors, batch file (as described above) should be used.
*NOTE: the .bat file should be included in the appropriate directory.

5. List of files needed for running the program:
[1] Blockchain.java
[2] .bat file (with appropriate commands--see above).

6. Notes:
Citations/Reference:
    Professor Clark Elliott, DePaul University
    http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
    https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
    https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html
    https://mkyong.com/java/how-to-parse-json-with-gson/
    http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
    https://www.mkyong.com/java/java-digital-signatures-example/
    https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
    https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
    https://www.mkyong.com/java/java-sha-hashing-example/
    https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
    https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
    https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @
    https://dzone.com/articles/generate-random-alpha-numeric
    http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example

----------------------------------------------------------*/
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.*;
import java.security.MessageDigest;
import java.security.*;
import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.util.Base64;
import java.util.Arrays;
import java.util.*;
import java.util.concurrent.*;
import java.util.Scanner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.*;
import java.text.*;
import java.net.*;
import javax.crypto.Cipher;

public class Blockchain {

    static private PrivateKey privateKey;
  
    private static String FILENAME;

    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
   
    public static String serverName = "localhost";
  
    public static final String ALGORITHM = "RSA";
    static int NUMPROCESSES = 3;
 
    public static int PID;

    public static LinkedList<BlockRecord> BLOCKCHAIN = new LinkedList<>();

    public static LinkedList<BlockRecord> RECORDLIST = new LinkedList<>();
 
    public static List<keyFactory> KEYLIST = new ArrayList<>();

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>(){
        @Override
        public int compare(BlockRecord b1, BlockRecord b2){
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };
    
    static Queue<BlockRecord> ourPriorityQueue = new PriorityQueue<>(100, BlockTSComparator);

    public static LinkedList<BlockRecord> readTxt(int pnum) {
        switch (pnum) {
            case 1: FILENAME = "BlockInput1.txt";break;
            case 2: FILENAME = "BlockInput2.txt";break;
            default: FILENAME = "BlockInput0.txt"; break;
        }
        try {
            BufferedReader br = new BufferedReader(new FileReader(FILENAME));
            String[] tokens = new String[10];
            String InputLineStr;
            String suuid;
            UUID idA;
            while ((InputLineStr = br.readLine()) != null) {
                BlockRecord BR = new BlockRecord();
                try{Thread.sleep(1001);}catch(InterruptedException e){}
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + pnum;
                suuid = new String(UUID.randomUUID().toString());
                idA = UUID.randomUUID();
                KeyPair keyPair = generateKeyPair(999);
                byte[] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
                String eSignature = Base64.getEncoder().encodeToString(digitalSignature);

                BR.setBlockID(suuid);
                BR.setTimeStamp(TimeStampString);
                BR.setUUID(idA);
                BR.seteSignature(eSignature);
                BR.setVerificationProcessID(Integer.toString(Blockchain.PID));
                BR.setRandomSeed(Blockchain.randomAlphaNumeric(8));
                tokens = InputLineStr.split(" +");
                BR.setFname(tokens[0]);
                BR.setLname(tokens[1]);
                BR.setDOB(tokens[2]);
                BR.setSSNum(tokens[3]);
                BR.setDiag(tokens[4]);
                BR.setTreat(tokens[5]);
                BR.setRx(tokens[6]);

                RECORDLIST.add(BR);
            }
        } catch (Exception e) {e.printStackTrace();}

        return RECORDLIST;
    }
 
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    public static keyFactory makeKey(int pnum){
        keyFactory KF = new keyFactory(); 
        try {
            Random rk = new Random(); 
            int rs = rk.nextInt(999); 
            KeyPair keyPair = generateKeyPair(rs); 
            PublicKey publicKey = keyPair.getPublic(); 
            privateKey = keyPair.getPrivate(); 
            String encodedPK = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            KF.setPnum(pnum); 
            KF.setPublicKey(encodedPK); 
        }catch (Exception x) {x.printStackTrace();}
        return KF;
    }

    public void KeySend (keyFactory KF){
        Socket sock; 
        PrintStream toServer; 
        try{
            Gson gson = new GsonBuilder().create();
            String json = gson.toJson(KF);
            for(int i=0; i < NUMPROCESSES; i++){
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i));
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(json); 
                toServer.flush(); 
                sock.close(); 
            }
        } catch (Exception x) {x.printStackTrace ();}
    }

    public void UnverifiedSend (BlockRecord b, int server){
        Socket UVBsock; 
        PrintStream toServerOOS; 
        try {
            Gson gson = new GsonBuilder().create();
            String json = gson.toJson(b);
            for (int i = 0; i < NUMPROCESSES; i++) {
                UVBsock = new Socket(serverName, server + (i));
                toServerOOS = new PrintStream(UVBsock.getOutputStream());
                toServerOOS.println(json); 
                toServerOOS.flush(); 
            }
        }catch (Exception x) {x.printStackTrace ();}
    }
    public static void winnerSend(LinkedList <BlockRecord> b, int server){
        Socket FSBsock; 
        PrintStream toServerOOS; 
        try {
            Gson gson = new GsonBuilder().create();
            String json = gson.toJson(b);
            for (int i = 0; i < NUMPROCESSES; i++) {
                FSBsock = new Socket(serverName, server + (i));
                toServerOOS = new PrintStream(FSBsock.getOutputStream());
                toServerOOS.println(json); 
                toServerOOS.flush(); 
                FSBsock.close(); 
            }
        }catch (Exception x) {x.printStackTrace ();}
    }

    public static void main(String args[]) {
        String suuid;
        UUID idA;
     
        if (args.length < 1) PID = 0;
        else if (args[0].equals("0")) PID = 0;
        else if (args[0].equals("1")) PID = 1;
        else if (args[0].equals("2")) PID = 2;

        new Ports().setPorts();

        if (PID != 0 || PID != 1 || PID ==2) {

            PublicKeyServer pks = new PublicKeyServer();
            new Thread (pks).start();
            try { Thread.sleep(1001); } catch (InterruptedException e) {}
         
            UnverifiedBlockServer ubs = new UnverifiedBlockServer();
            new Thread (ubs).start();
            try { Thread.sleep(1001); } catch (InterruptedException e) {}

            BlockchainServer bcs = new BlockchainServer();
            new Thread(bcs).start();
            try { Thread.sleep(1001); } catch (InterruptedException e) {}

            System.out.println("\nHELLO FROM PROCESS: [" + PID + "]\n");
        }
            try {
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + PID;

                suuid = new String(UUID.randomUUID().toString());
                idA = UUID.randomUUID();

                KeyPair keyPair = generateKeyPair(999);
                byte [] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
                String eSignature = Base64.getEncoder().encodeToString(digitalSignature);

                BlockRecord genesis = new BlockRecord();
                genesis.setBlockID(suuid);
                genesis.setTimeStamp(T1);
                genesis.setUUID(idA);
                genesis.seteSignature(eSignature);
                genesis.setVerificationProcessID("Genesis");
                genesis.setRandomSeed(Blockchain.randomAlphaNumeric(8));
                genesis.setFname("Alpha");
                genesis.setLname("alpha");
                genesis.setDOB("00-00-0000");
                genesis.setSSNum("000-00-0000");
                genesis.setDiag("zero");
                genesis.setTreat("00000000");
                genesis.setRx("more zeros please!");
                genesis.setChainPlacement(0);
                BLOCKCHAIN.add(genesis);

            } catch (Exception e) {e.printStackTrace();}
            readTxt(PID);
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            keyFactory keys = makeKey(PID);
            Blockchain ks = new Blockchain();
            ks.KeySend(keys);
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            for (int i=0; i<KEYLIST.size(); i++){
                System.out.println( "\nPUBLIC KEY FOR PROCESS: [" + KEYLIST.get(i).getPnum() + "]\n"
                        + KEYLIST.get(i).getPublicKey() +"\n");}
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            System.out.println("\nSENDING UNVERIFIED BLOCKS FROM PROCESS: [" + PID + "]\n");
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            
            Blockchain uvs = new Blockchain();
            for (int j = 0; j < RECORDLIST.size(); j++) {
                uvs.UnverifiedSend(RECORDLIST.get(j), Ports.UnverifiedBlockServerPortBase);}
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            Miner miner = new Miner();
            miner.start();
    }
}

class Ports {
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + (Blockchain.PID); 
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID);
        BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID); 
    }
}


class BlockRecord {
    String BlockID;
    String TimeStamp;
    String VerificationProcessID;
    UUID uuid;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String RandomSeed;
    String Diag;
    String Treat;
    String Rx;
    String eSignature;
    int chainPlacement;

    public String getBlockID() {return BlockID;}
    public void setBlockID(String BID){this.BlockID = BID;}

    public String getTimeStamp() {return TimeStamp;}
    public void setTimeStamp(String TS){this.TimeStamp = TS;}

    public String getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public UUID getUUID() {return uuid;}
    public void setUUID (UUID ud){this.uuid = ud;}

    public String getLname() {return Lname;}
    public void setLname (String LN){this.Lname = LN;}

    public String getFname() {return Fname;}
    public void setFname (String FN){this.Fname = FN;}

    public String getSSNum() {return SSNum;}
    public void setSSNum (String SS){this.SSNum = SS;}

    public String getDOB() {return DOB;}
    public void setDOB (String RS){this.DOB = RS;}

    public String getDiag() {return Diag;}
    public void setDiag (String D){this.Diag = D;}

    public String getTreat() {return Treat;}
    public void setTreat (String Tr){this.Treat = Tr;}

    public String getRx() {return Rx;}
    public void setRx (String Rx){this.Rx = Rx;}

    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed (String RS){this.RandomSeed = RS;}

    public String geteSignature() {return eSignature;}
    public void seteSignature(String ES) {this.eSignature = ES;}

    public int getChainPlacement(){return chainPlacement;}
    public void setChainPlacement(int CP){this.chainPlacement = CP;}

}

class PublicKeyWorker extends Thread {
    keyFactory KF = new keyFactory(); 
    Socket keySock; 
    PublicKeyWorker (Socket s) {keySock = s;} 
    public void run(){
        Gson gson = new Gson(); 
        try{

            BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
            String data = in.readLine (); 
            KF = gson.fromJson(data,keyFactory.class);
            Blockchain.KEYLIST.add(KF); 
            keySock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class PublicKeyServer implements Runnable {
    public void run(){
        int q_len = 6; 
        Socket keySock; 
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                keySock = servsock.accept(); 
                new PublicKeyWorker (keySock).start(); 
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockServer implements Runnable {
    public void run(){
        int q_len = 6; 
        Socket sock;
        System.out.println("\nStarting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try {
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = UVBServer.accept();
                new UnverifiedBlockWorker(sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }

    class UnverifiedBlockWorker extends Thread {
        Socket sock; 
        UnverifiedBlockWorker (Socket s) {sock = s;} 
        public void run(){
            Gson gson = new Gson(); 
            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String json = in.readLine(); 
                BlockRecord blockRecordData = gson.fromJson(json,BlockRecord.class);
                System.out.println("recieved: " + blockRecordData.getFname()+ " " + blockRecordData.getLname()
                        + " from process: [" + blockRecordData.getVerificationProcessID() +"]");
                Blockchain.ourPriorityQueue.add(blockRecordData);
            } catch (Exception x){x.printStackTrace();}
        }
    }
}

class BlockchainWorker extends Thread {
    Socket sock; 
    BlockchainWorker (Socket s) {sock = s;} 
    public void run(){
        Gson gson = new Gson(); 
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String blockDataIn = in.readLine(); 
            BlockRecord [] blockRecordData = gson.fromJson(blockDataIn,BlockRecord[].class);
            Gson gsonbuilder = new GsonBuilder().setPrettyPrinting().create();
            try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
                gsonbuilder.toJson(blockRecordData, writer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException x){x.printStackTrace();}
    }
}
class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; 
        Socket sock; 
        System.out.println("\nStarting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start(); 
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class keyFactory {
    String publicKey;
    int pnum;

    public int getPnum(){return this.pnum;}
    public void setPnum(int PN){ this.pnum = PN;}

    public String getPublicKey(){ return this.publicKey;}
    public void setPublicKey(String PK){this.publicKey = PK;}
}


class Miner extends Thread {
    public static String ByteArrayToString(byte[] ba) {
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for (int i = 0; i < ba.length; i++) {
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }
    static String randString; 
    public void run() {
        String concatString = "";
        String stringOut = ""; 
        try {
            int n = 1;
            System.out.println("\n<-----STARTING COMPUTATIONS (THE WORK BEGINS FOR PROCESS: ["
                    +Blockchain.PID+"])----->\n");
            while (true) {
                BlockRecord b = Blockchain.ourPriorityQueue.poll();
                if (b == null) {
                    System.out.println("\n<-----COMPUTATIONS COMPLETE (THE WORK IS DONE FOR PROCESS: ["
                            +Blockchain.PID+"])----->\n");
                    break; 
                }
                String bData = b.getBlockID() + b.getDiag() + b.getDOB() + b.getFname() + b.getLname() + b.getDiag()
                        + b.getRx() + b.getSSNum() + b.getRandomSeed() + b.geteSignature() + b.getTimeStamp();
                randString = Blockchain.randomAlphaNumeric(8);
                int workNumber = 0;
                boolean flag = true;
                while (flag) {
                    try { Thread.sleep(300);} catch (InterruptedException e) {}
                    randString = Blockchain.randomAlphaNumeric(8);
                    concatString = bData + randString;
                 
                    MessageDigest MD = MessageDigest.getInstance("SHA-256");
                    byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));

                    stringOut = ByteArrayToString(bytesHash);
                    System.out.println("HASH= " + stringOut);

                    workNumber = Integer.parseInt(stringOut.substring(0, 4), 16);

                    if (!(workNumber < 20000)) {
                        System.out.format("%d > 20,000 [STATUS= NOT SOLVED]\n", workNumber);
                    }
                    if (workNumber < 20000) {
                        flag = false;
                        System.out.format("%d < 20,000 [STATUS= SOLVED]\n", workNumber);
                        Date date = new Date();
                        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                        String TimeStampString = T1 + "." + Blockchain.PID;
                        b.setTimeStamp(T1);
                        b.setChainPlacement(n);
                        Blockchain.BLOCKCHAIN.add(b); 
                        Blockchain.winnerSend(Blockchain.BLOCKCHAIN, Ports.BlockchainServerPortBase);
                        n++; 
                        System.out.println("\n***BLOCK: [" + b.getChainPlacement() +
                                "] HAS BEEN ADDED TO THE CHAIN BY PROCESS: [" + b.getVerificationProcessID() +"]***\n");
                        break; 
                    }
                }
            }
        }catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
