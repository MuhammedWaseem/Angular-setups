import { Router } from '@angular/router';
import {
    HttpRequest,
    HttpEvent,
    HttpHandler,
    HttpHeaders,
    HttpInterceptor,
    HttpResponse
} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import * as _ from 'lodash';
import { AuthenticationService } from '@core/azure-ad/authentication.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

    constructor(private authenticationService: AuthenticationService
    ) {
    }

    intercept(req: HttpRequest<any>,
        next: HttpHandler): Observable<HttpEvent<any>> {
        return this.authenticationService.getToken().pipe(switchMap((token) => {
            const headers = this.addHeader(req, token);
            return next.handle(req.clone({
                headers: headers
            }));
        }));
    }

    addHeader(req: HttpRequest<any>, token) {
        const headers: HttpHeaders = req.headers;
        if (req.url.search('login') === -1) {
            // For each Request

            let httpheader = headers.set('Authorization', `Bearer ${token}`)
                .set('Content-Type', 'application/json')
                .set('Access-Control-Allow-Origin', '*')
                .set('Cache-Control', 'no-cache')
                .set('Pragma', 'no-cache')

            if (sessionStorage.getItem('impUserToken') !== null) {
                httpheader = httpheader.set('ImpersonatedAuthToken', sessionStorage.getItem('impUserToken'));
            }

            return httpheader;
        } else {
            // To get Api Token
            return headers.set('Content-Type', 'application/json');
        }

    }

}
