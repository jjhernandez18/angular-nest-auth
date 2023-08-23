import { JwtService } from '@nestjs/jwt';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

    constructor( 
        private _jwtService: JwtService,
        private _authService: AuthService
    ) {}

    async canActivate(
        context: ExecutionContext,
    ): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        if(!token) {
            throw new UnauthorizedException('No tiene acceso a la acción que intenta ejecutar.');
        }

        try {
            const payload = await this._jwtService.verifyAsync<JwtPayload>(
                token, { secret: process.env.JWT_KEY }
            );

            const user = await this._authService.findUserById(payload.id);
            if(!user || !user.isActive) throw new UnauthorizedException();

            request['user'] = user;
        } catch {
            throw new UnauthorizedException('No tiene acceso a la acción que intenta ejecutar.');
        }

        return Promise.resolve(true);
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers['authorization']?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
