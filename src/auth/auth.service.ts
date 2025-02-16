import { ForbiddenException, Injectable, Post } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    // generate pass
    const hash = await argon.hash(dto.password);

    // save new user in db

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
        select: {
          email: true,
          createdAt: true,
          id: true,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Creds taken');
        }
      }
    }
  }

  async signin(dto: AuthDto) {
    const findUser = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!findUser) throw new ForbiddenException('Creds Invalid');

    const pwMatch = await argon.verify(findUser.password, dto.password);

    if (!pwMatch) throw new ForbiddenException('Creds Invalid');

    const user = {
      createdAt: findUser.createdAt,
      updatedAt: findUser.updatedAt,
      firstName: findUser.firstName,
      lastName: findUser.lastName,
      email: findUser.email,
      id: findUser.id,
    };

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });

    return {
      access_token: token,
    };
  }
}
