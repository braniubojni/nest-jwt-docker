import { ApiProperty } from "@nestjs/swagger";
import {
  Model,
  Table,
  DataType,
  Column,
  BelongsToMany,
} from "sequelize-typescript";
import { Role } from "src/roles/roles.model";
import { UserRoles } from "src/roles/user-roles.model";

interface UserCreationAttrs {
  email: string;
  password: string;
}

@Table({ tableName: "users" })
export class User extends Model<User, UserCreationAttrs> {
  @ApiProperty({ example: "1", description: "Unique ID" })
  @Column({
    type: DataType.INTEGER,
    unique: true,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({ example: "example@mail.ru", description: "Email address" })
  @Column({
    type: DataType.STRING,
    unique: true,
    allowNull: false,
  })
  email: string;

  @ApiProperty({ example: "Abcd1234", description: "Password" })
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  password: string;

  @ApiProperty({ example: "true", description: "Banned or not" })
  @Column({
    type: DataType.BOOLEAN,
    defaultValue: false,
  })
  banned: boolean;

  @ApiProperty({ example: "For hooliganism", description: "Ban reason" })
  @Column({
    type: DataType.BOOLEAN,
    allowNull: true,
  })
  banReason: string;

  @BelongsToMany(() => User, () => UserRoles)
  roles: Role[];
}
