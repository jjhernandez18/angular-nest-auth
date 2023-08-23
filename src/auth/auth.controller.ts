import { AuthService } from './auth.service';
import { Controller, Post, Body, Get, UseGuards, Request } from '@nestjs/common';
import { LoginDto, CreateUserDto, RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response';


@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post()
    create(@Body() createUserDto: CreateUserDto) {
        return this.authService.create(createUserDto);
    }

    @Post('login')
    login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('register')
    register(@Body() registerDto: RegisterUserDto) {
        return this.authService.register(registerDto);
    }

    @UseGuards( AuthGuard )
    @Get()
    findAll() {
        return this.authService.findAll();
    }

    @UseGuards( AuthGuard )
    @Get('check-token')
    checkToken( @Request() req: Request ): LoginResponse {
        const user = req['user'];

        return {
            user,
            token: this.authService.getJWT({ id: user._id })
        };
    }
}
