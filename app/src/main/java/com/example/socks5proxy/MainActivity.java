package com.example.socks5proxy;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * reference: https://www.cnblogs.com/cc11001100/p/9949729.html
 */
public class MainActivity extends AppCompatActivity {

    public final String TAG = "ProxyServer";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        new Thread(new ServerThread()).start();

    }
    public class ServerThread implements Runnable {

        @Override
        public void run() {
            Socks5ProxyServer proxy = new Socks5ProxyServer();
            try {
                Log.d(TAG, "start the Proxy");
                proxy.startProxy();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static class Socks5ProxyServer {

        // server port
        private final Integer SERVICE_LISTENER_PORT = 10086;

        // max client number
        private final Integer MAX_CLIENT_NUM = 100;

        // current client number
        private AtomicInteger clientNumCount = new AtomicInteger();

        // SOCKS5
        private static final byte VERSION = 0X05;

        // RSV, should be 0
        private static final byte RSV = 0X00;

        // server ip address
        private String SERVER_IP_ADDRESS;

        private String TAG = "ProxyServer";

        {
            try {
                SERVER_IP_ADDRESS = InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        public class ClientHandler implements Runnable {

            private Socket clientSocket;
            private String clientIp;
            private int clientPort;

            public ClientHandler(Socket clientSocket) {
                this.clientSocket = clientSocket;
                this.clientIp = clientSocket.getInetAddress().getHostAddress();
                this.clientPort = clientSocket.getPort();
            }

            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            @Override
            public void run() {
                try {

                    negotiationCertificationMethod();

                    handleClientCommand();

                } catch (Exception e) {
                    handleLog("exception, " + e.getMessage());
                } finally {
                    close(clientSocket);
                    handleLog("client dead, current client count=%s", clientNumCount.decrementAndGet());
                }
            }

            // negotiate the authentication method with the client
            private void negotiationCertificationMethod() throws IOException {
                InputStream is = clientSocket.getInputStream();
                OutputStream os = clientSocket.getOutputStream();
                byte[] buff = new byte[255];

                is.read(buff, 0, 2);
                // socks version, should be 5
                int version = buff[0];
                // the authentication method supported by the client
                int methodNum = buff[1];

                if (version != VERSION) {
                    throw new RuntimeException("version must 0X05");
                } else if (methodNum < 1) {
                    throw new RuntimeException("method num must gt 0");
                }

                is.read(buff, 0, methodNum);
                List<METHOD> clientSupportMethodList = METHOD.convertToMethod(Arrays.copyOfRange(buff, 0, methodNum));
                handleLog("version=%s, methodNum=%s, clientSupportMethodList=%s", version, methodNum, clientSupportMethodList);

                // send response to the client without authentication
                buff[0] = VERSION;
                buff[1] = METHOD.NO_AUTHENTICATION_REQUIRED.rangeStart;
                os.write(buff, 0, 2);
                os.flush();
            }

            // start to handle the client's commands
            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            private void handleClientCommand() throws IOException {
                InputStream is = clientSocket.getInputStream();
                OutputStream os = clientSocket.getOutputStream();
                byte[] buff = new byte[255];
                // receive client's command
                is.read(buff, 0, 4);
                int version = buff[0];
                COMMAND command = COMMAND.convertToCmd(buff[1]);
                int rsv = buff[2];
                ADDRESS_TYPE addressType = ADDRESS_TYPE.convertToAddressType(buff[3]);
                if (rsv != RSV) {
                    throw new RuntimeException("RSV must 0X05");
                } else if (version != VERSION) {
                    throw new RuntimeException("VERSION must 0X05");
                } else if (command == null) {
                    sendCommandResponse(COMMAND_STATUS.COMMAND_NOT_SUPPORTED);
                    handleLog("not supported command");
                    return;
                } else if (addressType == null) {
                    sendCommandResponse(COMMAND_STATUS.ADDRESS_TYPE_NOT_SUPPORTED);
                    handleLog("address type not supported");
                    return;
                }

                String targetAddress = "";
                switch (addressType) {
                    case DOMAIN:
                        // if type=domain, then the first byte is the length of domain name
                        is.read(buff, 0, 1);
                        int domainLength = buff[0];
                        is.read(buff, 0, domainLength);
                        targetAddress = new String(Arrays.copyOfRange(buff, 0, domainLength));
                        break;
                    case IPV4:
                        // if type=IPV4, then read the ipv4 address(4 bytes)
                        is.read(buff, 0, 4);
                        targetAddress = ipAddressBytesToString(buff);
                        break;
                    case IPV6:
                        throw new RuntimeException("not support ipv6.");
                }

                is.read(buff, 0, 2);
                int targetPort = ((buff[0] & 0XFF) << 8) | (buff[1] & 0XFF);

                StringBuilder msg = new StringBuilder();
                msg.append("version=").append(version).append(", cmd=").append(command.name())
                        .append(", addressType=").append(addressType.name())
                        .append(", domain=").append(targetAddress).append(", port=").append(targetPort);
                handleLog(msg.toString());

                // handle client's command
                switch (command) {
                    case CONNECT:
                        handleConnectCommand(targetAddress, targetPort);
                    case BIND:
                        throw new RuntimeException("not support command BIND");
                    case UDP_ASSOCIATE:
                        throw new RuntimeException("not support command UDP_ASSOCIATE");
                }

            }

            // convert ip address from 4 byte to string
            private String ipAddressBytesToString(byte[] ipAddressBytes) {
                // first convert to int avoid negative
                return (ipAddressBytes[0] & 0XFF) + "." + (ipAddressBytes[1] & 0XFF) + "." + (ipAddressBytes[2] & 0XFF) + "." + (ipAddressBytes[3] & 0XFF);
            }

            // handle CONNECT command
            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            private void handleConnectCommand(String targetAddress, int targetPort) throws IOException {
                Socket targetSocket = null;
                try {
                    targetSocket = new Socket(targetAddress, targetPort);
                } catch (IOException e) {
                    sendCommandResponse(COMMAND_STATUS.GENERAL_SOCKS_SERVER_FAILURE);
                    return;
                }
                sendCommandResponse(COMMAND_STATUS.SUCCEEDED);
                new SocketForwarding(clientSocket, targetSocket).start();
            }

            private void sendCommandResponse(COMMAND_STATUS commandStatus) throws IOException {
                OutputStream os = clientSocket.getOutputStream();
                os.write(buildCommandResponse(commandStatus.rangeStart));
                os.flush();
            }

            private byte[] buildCommandResponse(byte commandStatusCode) {
                ByteBuffer payload = ByteBuffer.allocate(100);
                payload.put(VERSION);
                payload.put(commandStatusCode);
                payload.put(RSV);
//          payload.put(ADDRESS_TYPE.IPV4.value);
//          payload.put(SERVER_IP_ADDRESS.getBytes());
                payload.put(ADDRESS_TYPE.DOMAIN.value);
                byte[] addressBytes = SERVER_IP_ADDRESS.getBytes();
                payload.put((byte) addressBytes.length);
                payload.put(addressBytes);
                payload.put((byte) (((SERVICE_LISTENER_PORT & 0XFF00) >> 8)));
                payload.put((byte) (SERVICE_LISTENER_PORT & 0XFF));
                byte[] payloadBytes = new byte[payload.position()];
                payload.flip();
                payload.get(payloadBytes);
                return payloadBytes;
            }

            private void handleLog(String format, Object... args) {
                log("handle, clientIp=" + clientIp + ", port=" + clientPort + ", " + format, args);
            }

        }

        // forward traffic between the client and the target server
        public class SocketForwarding {

            private Socket clientSocket;
            private String clientIp;
            private Socket targetSocket;
            private String targetAddress;
            private int targetPort;

            public SocketForwarding(Socket clientSocket, Socket targetSocket) {
                this.clientSocket = clientSocket;
                this.clientIp = clientSocket.getInetAddress().getHostAddress();
                this.targetSocket = targetSocket;
                this.targetAddress = targetSocket.getInetAddress().getHostAddress();
                this.targetPort = targetSocket.getPort();
            }

            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            public void start() {
                OutputStream clientOs = null;
                InputStream clientIs = null;
                InputStream targetIs = null;
                OutputStream targetOs = null;
                long start = System.currentTimeMillis();
                try {

                    clientOs = clientSocket.getOutputStream();
                    clientIs = clientSocket.getInputStream();
                    targetOs = targetSocket.getOutputStream();
                    targetIs = targetSocket.getInputStream();

                    // 512K size
                    byte[] buff = new byte[1024 * 512];
                    while (true) {

                        boolean needSleep = true;
                        while (clientIs.available() != 0) {
                            int n = clientIs.read(buff);
                            targetOs.write(buff, 0, n);
                            transientLog("client to remote, bytes=%d", n);
                            needSleep = false;
                        }

                        while (targetIs.available() != 0) {
                            int n = targetIs.read(buff);
                            clientOs.write(buff, 0, n);
                            transientLog("remote to client, bytes=%d", n);
                            needSleep = false;
                        }

                        if (clientSocket.isClosed()) {
                            transientLog("client closed");
                            break;
                        }

                        // time out interval is 30 seconds
                        if (System.currentTimeMillis() - start > 30_000) {
                            transientLog("time out");
                            break;
                        }

                        // 如果本次循环没有数据传输，说明管道现在不繁忙，应该休息一下把资源让给别的线程
                        if (needSleep) {
                            try {
                                TimeUnit.MILLISECONDS.sleep(10);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }

                    }
                } catch (IOException e) {
                    transientLog("conn exception" + e.getMessage());
                } finally {
                    close(clientIs);
                    close(clientOs);
                    close(targetIs);
                    close(targetOs);
                    close(clientSocket);
                    close(targetSocket);
                }
                transientLog("done.");
            }

            private void transientLog(String format, Object... args) {
                log("forwarding, clientIp=" + clientIp + ", targetAddress=" + targetAddress + ", port=" + targetPort + ", " + format, args);
            }

        }

        // authentication method
        public enum METHOD {

            NO_AUTHENTICATION_REQUIRED((byte) 0X00, (byte) 0X00, "NO AUTHENTICATION REQUIRED"),
            GSSAPI((byte) 0X01, (byte) 0X01, "GSSAPI"),
            USERNAME_PASSWORD((byte) 0X02, (byte) 0X02, " USERNAME/PASSWORD"),
            IANA_ASSIGNED((byte) 0X03, (byte) 0X07, "IANA ASSIGNED"),
            RESERVED_FOR_PRIVATE_METHODS((byte) 0X80, (byte) 0XFE, "RESERVED FOR PRIVATE METHODS"),
            NO_ACCEPTABLE_METHODS((byte) 0XFF, (byte) 0XFF, "NO ACCEPTABLE METHODS");

            private byte rangeStart;
            private byte rangeEnd;
            private String description;

            METHOD(byte rangeStart, byte rangeEnd, String description) {
                this.rangeStart = rangeStart;
                this.rangeEnd = rangeEnd;
                this.description = description;
            }

            public boolean isMe(byte value) {
                return value >= rangeStart && value <= rangeEnd;
            }

            public static List<METHOD> convertToMethod(byte[] methodValues) {
                List<METHOD> methodList = new ArrayList<>();
                for (byte b : methodValues) {
                    for (METHOD method : METHOD.values()) {
                        if (method.isMe(b)) {
                            methodList.add(method);
                            break;
                        }
                    }
                }
                return methodList;
            }

        }

        // command type
        public enum COMMAND {
            CONNECT((byte) 0X01, "CONNECT"),
            BIND((byte) 0X02, "BIND"),
            UDP_ASSOCIATE((byte) 0X03, "UDP ASSOCIATE");

            byte value;
            String description;

            COMMAND(byte value, String description) {
                this.value = value;
                this.description = description;
            }

            public static COMMAND convertToCmd(byte value) {
                for (COMMAND cmd : COMMAND.values()) {
                    if (cmd.value == value) {
                        return cmd;
                    }
                }
                return null;
            }

        }

        // address type
        public enum ADDRESS_TYPE {
            IPV4((byte) 0X01, "the address is a version-4 IP address, with a length of 4 octets"),
            DOMAIN((byte) 0X03, "the address field contains a fully-qualified domain name.  The first\n" +
                    "   octet of the address field contains the number of octets of name that\n" +
                    "   follow, there is no terminating NUL octet."),
            IPV6((byte) 0X04, "the address is a version-6 IP address, with a length of 16 octets.");
            byte value;
            String description;

            ADDRESS_TYPE(byte value, String description) {
                this.value = value;
                this.description = description;
            }

            public static ADDRESS_TYPE convertToAddressType(byte value) {
                for (ADDRESS_TYPE addressType : ADDRESS_TYPE.values()) {
                    if (addressType.value == value) {
                        return addressType;
                    }
                }
                return null;
            }

        }

        // result
        public enum COMMAND_STATUS {
            SUCCEEDED((byte) 0X00, (byte) 0X00, "succeeded"),
            GENERAL_SOCKS_SERVER_FAILURE((byte) 0X01, (byte) 0X01, "general SOCKS server failure"),
            CONNECTION_NOT_ALLOWED_BY_RULESET((byte) 0X02, (byte) 0X02, "connection not allowed by ruleset"),
            NETWORK_UNREACHABLE((byte) 0X03, (byte) 0X03, "Network unreachable"),
            HOST_UNREACHABLE((byte) 0X04, (byte) 0X04, "Host unreachable"),
            CONNECTION_REFUSED((byte) 0X05, (byte) 0X05, "Connection refused"),
            TTL_EXPIRED((byte) 0X06, (byte) 0X06, "TTL expired"),
            COMMAND_NOT_SUPPORTED((byte) 0X07, (byte) 0X07, "Command not supported"),
            ADDRESS_TYPE_NOT_SUPPORTED((byte) 0X08, (byte) 0X08, "Address type not supported"),
            UNASSIGNED((byte) 0X09, (byte) 0XFF, "unassigned");

            private byte rangeStart;
            private byte rangeEnd;
            private String description;

            COMMAND_STATUS(byte rangeStart, byte rangeEnd, String description) {
                this.rangeStart = rangeStart;
                this.rangeEnd = rangeEnd;
                this.description = description;
            }

        }

        // log method
        private synchronized void log(String format, Object... args) {
            String msg = String.format(format, args);
            System.out.println(msg);
            Log.d(TAG, msg);
        }

        private void close(Closeable closeable) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public void startProxy() throws IOException {
            ServerSocket serverSocket = new ServerSocket(SERVICE_LISTENER_PORT);
            Log.d(TAG, "create the ServerSocket listen on port "+ SERVICE_LISTENER_PORT);
            while (true) {
                Log.d(TAG, "wait for connection");
                Socket socket = serverSocket.accept();
                Log.d(TAG, "new connection!");
                if (clientNumCount.get() >= MAX_CLIENT_NUM) {
                    log("client num run out.");
                    continue;
                }
                log("new client, ip=%s:%d, current client count=%s", socket.getInetAddress(), socket.getPort(), clientNumCount.get());
                clientNumCount.incrementAndGet();
                new Thread(new ClientHandler(socket), "client-handler-" + UUID.randomUUID().toString()).start();
            }

        }

    }
}
