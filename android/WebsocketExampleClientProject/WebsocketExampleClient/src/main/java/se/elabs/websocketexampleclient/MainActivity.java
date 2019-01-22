package se.elabs.websocketexampleclient;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;

import com.cossacklabs.themis.ISessionCallbacks;
import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.KeyGenerationException;
import com.cossacklabs.themis.KeypairGenerator;
import com.cossacklabs.themis.Keypair;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.PublicKey;
import com.cossacklabs.themis.SecureCellData;
import com.cossacklabs.themis.SecureCellException;
import com.cossacklabs.themis.SecureSession;
import com.cossacklabs.themis.SecureSessionException;
import com.cossacklabs.themis.SecureCell;

public class MainActivity extends Activity {
    private WebSocketClient mWebSocketClient;

    private Keypair keypair;
    private SecureSession secureSession;

    private final String deviceId = Build.MANUFACTURER + Build.MODEL;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            keypair = KeypairGenerator.generateKeypair();
        } catch (KeyGenerationException e) {
            e.printStackTrace();
        }

        connectWebSocket();

        if (savedInstanceState == null) {
            getFragmentManager().beginTransaction()
                    .add(R.id.container, new PlaceholderFragment())
                    .commit();
        }
    }

    @Override
    protected void onStart()
    {
        super.onStart();

        TextView textView = (TextView)findViewById(R.id.messages);
        SharedPreferences sharedPref = getPreferences(Context.MODE_PRIVATE);

        if (sharedPref.contains("history")) {

            try {
                SecureCell secureCell = new SecureCell(deviceId);

                SecureCellData protectedData = new SecureCellData(Base64.decode(sharedPref.getString("history", ""), Base64.DEFAULT), null);

                textView.setText(new String(secureCell.unprotect(deviceId.getBytes("UTF-8"), protectedData), "UTF-8"));

            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (NullArgumentException e) {
                e.printStackTrace();
            } catch (InvalidArgumentException e) {
                e.printStackTrace();
            } catch (SecureCellException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onStop() {
        TextView textView = (TextView)findViewById(R.id.messages);

        SharedPreferences sharedPref = getPreferences(Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPref.edit();

        try {
            SecureCell secureCell = new SecureCell(deviceId);
            SecureCellData protectedData = secureCell.protect(deviceId.getBytes("UTF-8"), textView.getText().toString().getBytes("UTF-8"));

            editor.putString("history", Base64.encodeToString(protectedData.getProtectedData(), Base64.DEFAULT));
            editor.commit();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NullArgumentException e) {
            e.printStackTrace();
        } catch (SecureCellException e) {
            e.printStackTrace();
        }

        super.onStop();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        switch (item.getItemId()) {
            case R.id.action_settings:
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * A placeholder fragment containing a simple view.
     */
    public static class PlaceholderFragment extends Fragment {

        public PlaceholderFragment() {
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                Bundle savedInstanceState) {
            View rootView = inflater.inflate(R.layout.fragment_main, container, false);
            return rootView;
        }
    }

    private void connectWebSocket() {
        URI uri;
        try {
            // important: 127.0.0.1 doesn't work
            // use your own IP address
            // https://stackoverflow.com/questions/18979546/connection-refused-in-android-client
            uri = new URI("ws://10.10.1.38:8080");
        } catch (URISyntaxException e) {
            e.printStackTrace();
            return;
        }

        try {
            secureSession = new SecureSession(
                    deviceId.getBytes("UTF-8"),
                    keypair.getPrivateKey(),
                    new ISessionCallbacks() {
                        @Override
                        public PublicKey getPublicKeyForId(SecureSession secureSession, byte[] bytes) {
                            return new PublicKey(new byte[]{0x55, 0x45, 0x43, 0x32, 0x00, 0x00, 0x00, 0x2d, 0x75, 0x58, 0x33, (byte)0xd4, 0x02, 0x12, (byte)0xdf, 0x1f, (byte)0xe9, (byte)0xea, 0x48, 0x11, (byte)0xe1, (byte)0xf9, 0x71, (byte)0x8e, 0x24, 0x11, (byte)0xcb, (byte)0xfd, (byte)0xc0, (byte)0xa3, 0x6e, (byte)0xd6, (byte)0xac, (byte)0x88, (byte)0xb6, 0x44, (byte)0xc2, (byte)0x9a, 0x24, (byte)0x84, (byte)0xee, 0x50, 0x4c, 0x3e, (byte)0xa0});
                        }

                        @Override
                        public void stateChanged(final SecureSession secureSession) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    TextView textView = (TextView)findViewById(R.id.messages);
                                    textView.setText(textView.getText() + "\n" + secureSession.getState().name());
                                }
                            });
                        }
                    }
            );
        } catch (SecureSessionException e) {
            e.printStackTrace();
            return;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return;
        }

        mWebSocketClient = new WebSocketClient(uri) {

            @Override
            public void onOpen(ServerHandshake serverHandshake) {
                Log.i("Websocket", "Opened");

                mWebSocketClient.send(deviceId + ":" + Base64.encodeToString(keypair.getPublicKey().toByteArray(), Base64.DEFAULT));
                try {
                    mWebSocketClient.send(Base64.encodeToString(secureSession.generateConnectRequest(), Base64.DEFAULT));
                } catch (SecureSessionException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onMessage(String s) {

                byte[] wrappedData = Base64.decode(s, Base64.DEFAULT);
                try {
                    SecureSession.UnwrapResult unwrapResult = secureSession.unwrap(wrappedData);

                    switch (unwrapResult.getDataType()) {
                        case PROTOCOL_DATA:
                            mWebSocketClient.send(Base64.encodeToString(unwrapResult.getData(), Base64.DEFAULT));
                            break;
                        case NO_DATA:
                            break;
                        case USER_DATA:
                            final String message = new String(unwrapResult.getData(), "UTF-8");
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    TextView textView = (TextView)findViewById(R.id.messages);
                                    textView.setText(textView.getText() + "\n" + message);
                                }
                            });
                            break;
                    }
                } catch (SecureSessionException e) {
                    e.printStackTrace();
                } catch (NullArgumentException e) {
                    e.printStackTrace();
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onClose(int i, String s, boolean b) {
                secureSession.close();
                Log.i("Websocket", "Closed " + s);
            }

            @Override
            public void onError(Exception e) {
                Log.i("Websocket", "Error " + e.getMessage());
            }
        };
        mWebSocketClient.connect();
    }

    public void sendMessage(View view) {
        EditText editText = findViewById(R.id.message);

        try {
            byte[] message = editText.getText().toString().getBytes("UTF-8");
            byte[] wrapped = secureSession.wrap(message);
            mWebSocketClient.send(Base64.encodeToString(wrapped, Base64.DEFAULT));
        } catch (SecureSessionException e) {
            e.printStackTrace();
        } catch (NullArgumentException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        editText.setText("");
    }
}
