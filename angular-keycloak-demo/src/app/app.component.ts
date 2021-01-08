import { Component, OnInit } from '@angular/core';

import { get } from 'scriptjs';
declare var Keycloak: any;

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit {
  constructor () {}

  ngOnInit() {
    console.log("Debug: the first component.");
  }
}
