import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { hash, verify } from 'argon2';
@Injectable()
export class AuthService {
  constructor(private readonly userService: UserService){}
  registerUser(createUserDto: CreateUserDto){
    const user = this.userService.findByEmail(createUserDto.email);
    if (user) throw new ConflictException('User already exists!');
    return this.userService.create(createUserDto);
  }

  async validateLocalUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new UnauthorizedException('User not found!');
    const isPasswordMatched = verify(user.password, password);
    if (!isPasswordMatched)
      throw new UnauthorizedException('Invalid Credentials!');

    return { id: user.id, name: user.name, role: user.role };
  }
}
