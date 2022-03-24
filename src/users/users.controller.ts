import { Body, Controller, Get, Post, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { JwtAuthGuard } from "src/auth/jwt-auth.guard";
import { Roles } from "src/auth/roles-auth.decorator";
import { RolesController } from "src/roles/roles.controller";
import { AddRoleDto } from "./dto/add-role.dto";
import { CreateUserDto } from "./dto/create-user.dto";
import { User } from "./users.model";
import { UsersService } from "./users.service";

@ApiTags("Users")
@Controller("users")
export class UsersController {
  constructor(private usersService: UsersService) {}

  @ApiOperation({ summary: "User creation" })
  @ApiResponse({ status: 200, type: User })
  @Post()
  create(@Body() userDto: CreateUserDto) {
    return this.usersService.createUser(userDto);
  }

  @ApiOperation({ summary: "Get all users" })
  @ApiResponse({ status: 200, type: [User] })
  @UseGuards(JwtAuthGuard)
  @Roles("ADMIN")
  @Get()
  getAll() {
    return this.usersService.getAllUsers();
  }

  // @ApiOperation({ summary: "Role issuing" })
  // @ApiResponse({ status: 200 })
  // @Roles("ADMIN")
  // @UseGuards(JwtAuthGuard)
  // @Get('/role')
  // addRole() {
  //   return this.usersService.addRole(dto: AddRoleDto);
  // }
}
