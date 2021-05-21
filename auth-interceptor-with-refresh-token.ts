import { Inject, Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { BehaviorSubject, Observable, throwError } from 'rxjs';
import { AuthenticationService } from './authentication.service';
import { catchError, switchMap, filter, take } from 'rxjs/operators';
import { WINDOW } from '../window.provider';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

    private isRefreshing = false;
    private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);

    constructor(public authService: AuthenticationService, @Inject(WINDOW) private window: Window) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

        const req = this.addHeader(request, this.authService.getToken());

        return next.handle(req).pipe(catchError(error => {
            if (this.authService.isUserLoggedIn) {
                if (error instanceof HttpErrorResponse && error.status === 401) {
                    return this.handle401Error(request, next);
                } else {
                    return throwError(error);
                }
            }
        }));
    }

    addHeader(req: HttpRequest<any>, token) {
        let headers: HttpHeaders = req.headers
            .set('Access-Control-Allow-Origin', '*')
            .set('Content-Type', 'application/json')
            // Explicitly setting request orgin header as swagger is not allowing to add/override orgin header
            //.set('request-origin', 'webstoragekaap.z6.web.core.windows.net');
            .set('request-origin', this.getHostname());
        if (req.url.search('/login') === -1) {
            // For each Request

            headers = headers.set('Authorization', `Bearer ${token}`)
                .set('Content-Type', 'application/json')
                .set('Cache-Control', 'no-cache')
                .set('Pragma', 'no-cache');

            // if (sessionStorage.getItem('impUserToken') !== null) {
            //     httpheader = httpheader.set('ImpersonatedAuthToken', sessionStorage.getItem('impUserToken'));
            // }
        }
        return req.clone({ headers });
    }

    private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
        if (!this.isRefreshing) {
            this.isRefreshing = true;
            this.refreshTokenSubject.next(null);

            return this.authService.refreshToken(this.handleRefreshError).pipe(
                switchMap((res: any) => {
                    this.isRefreshing = false;
                    this.refreshTokenSubject.next(res.token);
                    this.authService.setRefreshToken(res);
                    return next.handle(this.addHeader(request, res.token));
                }));

        } else {
            return this.refreshTokenSubject.pipe(
                filter(token => token != null),
                take(1),
                switchMap(jwt => {
                    return next.handle(this.addHeader(request, jwt));
                }));
        }
    }

    private handleRefreshError = (error: string) => {
        if (error) {
            this.authService.logout(true);
        }
    }

    private getHostname(): string {
        return this.window.location.hostname;
    }
}
