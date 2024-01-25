import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterOutlet } from '@angular/router';
import { EncryptedURI } from '@encrypted-uri/core';

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
    password: ['', [
      Validators.required.bind(this)
    ]],
    kdfHasher: ['sha256', [
      Validators.required.bind(this)
    ]],
    kdfRounds: ['32', [
      Validators.required.bind(this)
    ]],
    kdfDerivateKeyLength: ['32', [
      Validators.required.bind(this)
    ]]
  });

  decryptForm = this.formBuilder.group({
    uri: ['', [
      Validators.required.bind(this)
    ]],
    password: ['', [
      Validators.required.bind(this)
    ]],
    kdfHasher: ['sha256', [
      Validators.required.bind(this)
    ]],
    kdfRounds: ['32', [
      Validators.required.bind(this)
    ]],
    kdfDerivateKeyLength: ['32', [
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

  onEncryptSubmit(): void {
    if (this.encryptForm.valid) {
      const raw = this.encryptForm.getRawValue();
      if (raw.algorithm && raw.content && raw.password) {
        EncryptedURI.encrypt({
          algorithm: raw.algorithm,
          content: raw.content,
          password: raw.password,
          kdf: {
            kdf: 'pbkdf2',
            includeURIParams: true,
            ignoreDefaults: true,
            hasher: 'sha256',
            rounds: 100_000,
            derivateKeyLength: 32
          }
        })
        .then(uri => this.generatedEncryptedURI = uri)
        .catch(e => console.error(e));
      }
    }
  }

  onDecryptSubmit(): void {
    if (this.decryptForm.valid) {
      const raw = this.decryptForm.getRawValue();
      if (raw.uri && raw.password) {
        EncryptedURI
          .decrypt(raw.uri, raw.password, {
            hasher: 'sha256',
            rounds: 100_000,
            derivateKeyLength: 32
          })
          .then(decrypted => this.decryptedContent = decrypted)
          .catch(e => console.error(e));
      }
    }
  }
}
