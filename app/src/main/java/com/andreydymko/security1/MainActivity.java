package com.andreydymko.security1;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;

import com.andreydymko.security1.AES.AES;
import com.andreydymko.security1.RSA.RSA;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private EditText editTextInput, editTextKey, editTextOutput;
    private Button buttonEncrypt, buttonDecrypt;
    private ImageButton buttonMoveOutIntoIn;
    private AES aesEncrypter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_aes);

        aesEncrypter = new AES(256);

        editTextInput = findViewById(R.id.editTextMultiLineInput);
        editTextOutput = findViewById(R.id.editTextMultiLineOutput);

        editTextKey = findViewById(R.id.editTextKey);

        buttonEncrypt = findViewById(R.id.buttonEncrypt);
        buttonDecrypt = findViewById(R.id.buttonDecrypt);
        buttonEncrypt.setOnClickListener(this);
        buttonDecrypt.setOnClickListener(this);

        buttonMoveOutIntoIn = findViewById(R.id.buttonMoveOutIntoIn);
        buttonMoveOutIntoIn.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.buttonEncrypt:
                editTextOutput.setText(
                        new String(
                                aesEncrypter.encrypt(editTextInput.getText().toString().getBytes(StandardCharsets.UTF_16LE),
                                        editTextKey.getText().toString().getBytes(StandardCharsets.UTF_16LE)),
                                StandardCharsets.ISO_8859_1));
                break;
            case R.id.buttonDecrypt:
                editTextOutput.setText(
                        new String(
                                aesEncrypter.decrypt(editTextInput.getText().toString().getBytes(StandardCharsets.ISO_8859_1),
                                        editTextKey.getText().toString().getBytes(StandardCharsets.UTF_16LE)),
                                StandardCharsets.UTF_16LE));
                break;
            case R.id.buttonMoveOutIntoIn:
                editTextInput.setText(editTextOutput.getText());
                editTextOutput.getText().clear();
                break;
            default:
                break;
        }
    }
}