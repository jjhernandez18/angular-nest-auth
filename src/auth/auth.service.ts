import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from "bcryptjs";
import { JwtPayload } from './interfaces/jwt-payload';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose'; 
import { LoginResponse } from './interfaces/login-response';
import { CreateUserDto, RegisterUserDto, LoginDto } from './dto';
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';


@Injectable()
export class AuthService {

    constructor(
        @InjectModel( User.name ) private userModel: Model<User>,
        private jwtService: JwtService
    ) {}

    async create(createUserDto: CreateUserDto): Promise<User> {
        try {
            const { password, ...userData } = createUserDto;
            const newUser = new this.userModel({
                password: bcryptjs.hashSync( password, 10 ),
                ...userData
            });

            await newUser.save();

            const { password:_, ... user } = newUser.toJSON(); 
            return user;

        } catch (error) {
            if( error.code === 11000 ) {
                throw new BadRequestException(`El e-mail [${ createUserDto.email }] está en uso!`);
            }

            throw new InternalServerErrorException('Algo en la petición está mal!');
        }
    }

    async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {
        const user = await this.create( registerDto );

        return {
            user,
            token: this.getJWT({ id: user._id })
        }
    }

    async login(loginDto: LoginDto): Promise<LoginResponse> {
        const { email, password } = loginDto;
        const user = await this.userModel.findOne({ email });

        if(!user) {
            throw new UnauthorizedException('El usuario no existe.');
        }

        if( !bcryptjs.compareSync( password, user.password ) ) {
            throw new UnauthorizedException('Las credenciales no son válidas.');
        }

        const { password:_, ...rest } = user.toJSON();

        return {
            user: rest,
            token: this.getJWT({ id: user.id })
        };
    }

    async findAll(): Promise<User[]> {
        return this.userModel.find();
    }

    async findUserById( userId:string ) {
        const user = await this.userModel.findById(userId);
        const { password, ...rest } = user.toJSON();

        return rest;
    }

    getJWT( payload: JwtPayload ) {
        const token = this.jwtService.sign(payload);

        return token;
    }
}
