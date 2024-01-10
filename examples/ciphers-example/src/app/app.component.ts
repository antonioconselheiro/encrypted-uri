import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
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

  onEncryptSubmit(): void {
    if (this.encryptForm.valid) {
      const raw = this.encryptForm.getRawValue();
      if (raw.algorithm && raw.content && raw.key) {
        EncryptedURI.encrypt({
          algorithm: raw.algorithm,
          content: raw.content,
          key: raw.key
        }).then(uri => {
          this.generatedEncryptedURI = uri;
        });
      }
    }
  }

  onDecryptSubmit(): void {
    if (this.decryptForm.valid) {
      const raw = this.decryptForm.getRawValue();
      if (raw.uri && raw.key) {
        EncryptedURI
          .decrypt(raw.uri, raw.key)
          .then(decrypted => this.decryptedContent = decrypted);
      }
    }
  }
}
