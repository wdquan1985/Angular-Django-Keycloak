import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

import { HttpHeaders, HttpClient,  } from '@angular/common/http';
import { KeycloakService } from 'keycloak-angular';
// declare var Keycloak: any;

@Component({
  selector: 'app-home-page',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  constructor(
    private router: Router,
    private http: HttpClient,
    private keycloakService: KeycloakService
  ) {}

  isAuthenticated: boolean;

  brucetest: any;
  testString: string = "bruce";

  ngOnInit() {
    console.log("Debug: the second component.");
    this.getBackendInfo();
  }

  //Bruce
  ngOnDestroy(){
    this.logout();
  }

  getBackendInfo(){
    let cookie_token="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNS1FBX0VtX3JVNGhLOVhqMG9qU0pMckRDZ25RRjdRam9MZ2JMOXRjQTQ4In0";
    document.cookie ="keycloakToken=" + cookie_token;
    this.brucetest = JSON.stringify({"hello":"bruce"});
    this.http.get(`/api/adminresource/`).subscribe(
      response => {
        console.log("Debug: the value of res is " + JSON.stringify(response));
        this.brucetest = JSON.stringify(response);
      },
      err => {
        console.log("Debug: error message" + err);
      }
    )

  }

  logout(){
    this.keycloakService.logout(window.location.protocol + "//" + window.location.host);
  }


}
