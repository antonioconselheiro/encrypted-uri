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

  encryptForm = this.formBuilder.group({
    algorithm: ['aes/cbc', [
      Validators.required.bind(this)
    ]],
    content: ['', [
      Validators.required.bind(this)
    ]],
    key: ['', [
      Validators.required.bind(this)
    ]]
  });

  decryptForm = this.formBuilder.group({
    encoded: ['', [
      Validators.required.bind(this)
    ]],
    key: ['', [
      Validators.required.bind(this)
    ]]
  });

  constructor(
    private formBuilder: FormBuilder
  ) { }

  onEncryptSubmit(): void {
    if (this.encryptForm.valid) {
      const raw = this.encryptForm.getRawValue();
      this.generatedEncryptedURI = EncryptedURI.encrypt({
        algorithm: raw.algorithm,
        content: raw.content
     }, raw.key);
    }
  }

  onDecryptSubmit(): void {
    if (this.decryptForm.valid) {
      const raw = this.decryptForm.getRawValue();
      console.info(EncryptedURI.decrypt(raw.encoded, raw.key));
    }
  }
}
