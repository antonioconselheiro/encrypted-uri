import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { EncryptedURI } from '@encrypted-uri/core';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    RouterOutlet,
    ReactiveFormsModule
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {

  generatedEncryptedURI?: string;
  decryptedContent?: string;

  submittedEncrypt = false;
  submittedDecrypt = false;

  encryptForm = this.formBuilder.group({
    algorithm: ['aes/cbc', [
      Validators.required.bind(this)
    ]],
    content: ['', [
      Validators.required.bind(this)
    ]],
    kdf: ['', [
      Validators.required.bind(this)
    ]],
    password: ['', [
      Validators.required.bind(this)
    ]]
  });

  decryptForm = this.formBuilder.group({
    uri: ['', [
      Validators.required.bind(this)
    ]],
    kdf: ['', [
      Validators.required.bind(this)
    ]],
    password: ['', [
      Validators.required.bind(this)
    ]]
  });

  constructor(
    private formBuilder: FormBuilder
  ) { }

  getEncryptErrors(property: string, errorName: string): boolean {
    const controls: any = this.encryptForm.controls;
    return this.submittedEncrypt && controls[property].errors[errorName] || false;
  }

  getDecryptErrors(property: string, errorName: string): boolean {
    const controls: any = this.decryptForm.controls;
    return this.submittedDecrypt && controls[property].errors[errorName] || false;
  }

  private getKeyFromPasswordBasedKDF2(password: string, salt: Uint8Array): Uint8Array {
    return pbkdf2(sha256, password, salt, { c: 1, dkLen: 32 });
  }

  onEncryptSubmit(): void {
    if (this.encryptForm.valid) {
      const salt = randomBytes(32);
      const raw = this.encryptForm.getRawValue();
      if (raw.algorithm && raw.content && raw.password) {
        EncryptedURI.encrypt({
          algorithm: raw.algorithm,
          content: raw.content,
          password: raw.password,
          kdf: {
            hasher: 'sha256',
            rounds: 1,
            derivateKeyLength: 32
          }
        }).then(uri => {
          this.generatedEncryptedURI = uri;
        });
      }
    }
  }

  onDecryptSubmit(): void {
    if (this.decryptForm.valid) {
      const raw = this.decryptForm.getRawValue();
      if (raw.uri && raw.password) {
        EncryptedURI
          .decrypt(raw.uri, raw.password, {
            kdf: {
              hasher: sha256,
              rounds: 1,
              derivateKeyLength: 32
            }
          })
          .then(decrypted => this.decryptedContent = decrypted);
      }
    }
  }
}
