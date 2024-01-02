import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';
import { supportAES } from '@encrypted-uri/ciphers';

supportAES();

bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));
