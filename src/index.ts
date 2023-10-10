#! /usr/bin/env node

import { Command } from 'commander'
// @ts-ignore
import { version } from '../package.json'
import prompt from 'prompt-sync'
import colors from 'colors'
import fs from 'fs-extra'
import { exec } from 'child_process'

colors.enable();

const program = new Command();

program
    .name("@maxvzl-cli")
    .description("A MaxVzl CLI")
    .version(version);

program.command('init:auth')
    .description('Initialize authentication')
    .action(() => {
        console.log('Initializing authentication...');

        let userModelName = prompt()('User model name (default: User): ');

        if (userModelName === '') {
            userModelName = 'User';
        }

        fs.ensureFileSync('./src/components/layouts/auth/authenticated-layout.tsx');
        fs.appendFileSync('./src/components/layouts/auth/authenticated-layout.tsx', `import {redirect} from "next/navigation";
import {verifyToken} from "../../../lib/auth/auth";
import {getUser} from "../../../lib/auth/user";
import {UserRole} from "@prisma/client";
import {AuthDataType} from "../../../types/auth/auth";
import {AuthProvider} from "../../providers/auth/auth-provider";

type AuthenticatedLayoutProps = {
    children: React.ReactNode,
    redirectURL?: string, // Redirect to this URL if the user is not authenticated (default: '/auth/login')
    roles?: UserRole[], // Roles that are allowed to access this page (example: ['USER', 'ADMIN'])
    rolesRedirectURL?: string // Redirect to this URL if the user is not allowed to access this page (default: '/')
}

export default async function AuthenticatedLayout({ children, redirectURL, roles, rolesRedirectURL }: AuthenticatedLayoutProps) {
    const verifiedToken = await verifyToken().catch((err) => {
        console.error(err.message);
    });

    if (!verifiedToken) {
        redirect(redirectURL || '/auth/login');
    }

    const user = await getUser();

    if (!user) {
        redirect(redirectURL || '/auth/login');
    }

    if (roles) {
        if (!roles.every((role) => user.roles.includes(role))) {
            redirect(rolesRedirectURL || '/');
        }
    }

    const data: AuthDataType = {
        user: user
    };

    return (
        <AuthProvider data={data}>
            {children}
        </AuthProvider>
    )
}`);
        fs.ensureFileSync('./src/components/layouts/auth/guest-layout.tsx');
        fs.appendFileSync('./src/components/layouts/auth/guest-layout.tsx', `import {redirect} from "next/navigation";
import {verifyToken} from "../../../lib/auth/auth";

type GuestLayoutProps = {
    children: React.ReactNode
    redirectURL?: string // Redirect to this URL if the user is authenticated (default: '/dashboard')
}

export default async function GuestLayout({ children, redirectURL }: GuestLayoutProps) {
    const verifiedToken = await verifyToken().catch((err) => {
        console.error(err.message);
    });

    if (verifiedToken) {
        redirect(redirectURL || '/dashboard');
    }

    return (
        <>{children}</>
    )
}`);
        fs.ensureFileSync('./src/components/layouts/auth/universal-layout.tsx');
        fs.appendFileSync('./src/components/layouts/auth/universal-layout.tsx', `import {verifyToken} from "../../../lib/auth/auth";
import {getUser} from "../../../lib/auth/user";
import {AuthDataType} from "../../../types/auth/auth";
import {AuthProvider} from "../../providers/auth/auth-provider";

type UniversalLayoutProps = {
    children: React.ReactNode,
}

export default async function UniversalLayout({ children }: UniversalLayoutProps) {
    const verifiedToken = await verifyToken().catch((err) => {
        console.error(err.message);
    });

    const data: AuthDataType = {
        user: null
    };

    if (verifiedToken) {
        data.user = await getUser();
    }

    return (
        <AuthProvider data={data}>
            {children}
        </AuthProvider>
    )
}`);
        fs.ensureFileSync('./src/components/providers/auth/auth-provider.tsx');
        fs.appendFileSync('./src/components/providers/auth/auth-provider.tsx', `'use client';

import {User} from "@prisma/client";
import {useEffect, useState} from "react";
import {AuthContext} from "../../../context/auth/auth-context";
import {AuthDataType} from "../../../types/auth/auth";

type AuthProviderProps = {
    children: React.ReactNode;
    data: AuthDataType;
}

export const AuthProvider = ({children, data}: AuthProviderProps) => {
    const [user, setUser] = useState<User | null>(null);

    useEffect(() => {
        setUser(data.user);
    }, [data]);

    return (
        <AuthContext.Provider value={{user, setUser}}>
            {children}
        </AuthContext.Provider>
    );
}`);
        fs.ensureFileSync('./src/context/auth/auth-context.ts');
        fs.appendFileSync('./src/context/auth/auth-context.ts', `'use client';

import {createContext, Dispatch, SetStateAction, useContext, useEffect, useState} from "react";
import {User} from "@prisma/client";

interface ContextProps {
    user: User | null;
    setUser: Dispatch<SetStateAction<User | null>>;
}

export const AuthContext = createContext<ContextProps>({
    user: {} as User,
    setUser: (): User => ({} as User)
});

export const useAuthContext = () => useContext(AuthContext);`);
        fs.ensureFileSync('./src/lib/auth/auth.ts');
        fs.appendFileSync('./src/lib/auth/auth.ts', `'use server'

import {jwtVerify, SignJWT} from 'jose';
import prisma from "../../lib/auth/prisma";
import {cookies} from "next/headers";
import {z} from "zod";
import {LoginDataType, RegisterDataType} from "../../types/auth/auth";
import {redirect} from "next/navigation";
import {createHash} from "crypto";

export const verifyToken = async () => {
    const token = cookies().get('user-token')?.value as string;
    return await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET as string));
}

export const login = async (data: LoginDataType) => {
    // verify if email and password are not empty
    if (!data.email || !data.password) {
        throw new Error('Missing email and/or password');
    }

    // verify if email exists
    const user = await prisma.user.findUnique({
        where: {
            email: data.email
        }
    });
    if (!user) {
        throw new Error('Email does not exist');
    }

    // Hash password
    const hash = createHash('sha256').update(data.password).digest('hex')

    // verify if password is correct
    if (user.password !== hash) {
        throw new Error('Password is incorrect');
    }

    // create jwt token
    const token = await new SignJWT({id: user.id})
        .setProtectedHeader({alg: 'HS256'})
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(new TextEncoder().encode(process.env.JWT_SECRET as string));

    // set cookie with jwt token
    cookies().set('user-token', token, {
        httpOnly: true,
    });

    redirect('/dashboard');
}

export const logout = () => {
    // delete cookie with jwt token
    cookies().delete('user-token')

    redirect('/auth/login');
}

export const register = async (data: RegisterDataType) => {
    // verify if name, email, password and confirm_password are not empty
    if (!data.name || !data.email || !data.password || !data.confirm_password) {
        throw new Error('Missing name, email, password and/or confirm_password');
    }

    // verify if password and confirm_password are the same
    if (data.password !== data.confirm_password) {
        throw new Error('Password and confirm password are not the same');
    }

    // verify if email already exists
    const user = await prisma.user.findUnique({
        where: {
            email: data.email
        }
    });
    if (user) {
        throw new Error('Email already exists');
    }

    // verify if password is strong enough
    const passwordSchema = z.string().min(8).max(100).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/);
    if (!passwordSchema.safeParse(data.password).success) {
        throw new Error('Password is not strong enough');
    }

    // Hash password
    const hash = createHash('sha256').update(data.password).digest('hex')

    // create user
    const newUser = await prisma.user.create({
        data: {
            email: data.email,
            password: hash
        }
    });

    // create jwt token
    const token = await new SignJWT({id: newUser.id})
        .setProtectedHeader({alg: 'HS256'})
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(new TextEncoder().encode(process.env.JWT_SECRET as string));

    // set cookie with jwt token
    cookies().set('user-token', token, {
        httpOnly: true,
    });

    redirect('/dashboard');
}`);
        fs.ensureFileSync('./src/lib/auth/prisma.ts');
        fs.appendFileSync('./src/lib/auth/prisma.ts', `import { PrismaClient } from '@prisma/client';

let prisma: PrismaClient;

const globalForPrisma = global as unknown as { prisma: PrismaClient };

if (process.env.NODE_ENV === 'production') {
    prisma = new PrismaClient();
} else {
    if (!globalForPrisma.prisma) {
        globalForPrisma.prisma = new PrismaClient();
    }
    prisma = globalForPrisma.prisma;
}

export default prisma;`);
        fs.ensureFileSync('./src/lib/auth/user.ts');
        fs.appendFileSync('./src/lib/auth/user.ts', `'use server'

import prisma from "../../lib/auth/prisma";
import {cookies} from "next/headers";
import {decodeJwt} from "jose";

export const getUserId = () => {
    const token = cookies().get('user-token')?.value;
    const payload = token ? decodeJwt(token) : null;
    if (payload) {
        return payload.id as number
    } else {
        return 0;
    }
}

export const getUser = async () => {
    return prisma.user.findUnique({
        where: {
            id: getUserId()
        }
    });
}`);
        fs.ensureFileSync('./src/types/auth/auth.ts');
        fs.appendFileSync('./src/types/auth/auth.ts', `import {User} from "@prisma/client";
        
export type LoginDataType = {
    email: string;
    password: string;
}

export type RegisterDataType = {
    name: string;
    email: string;
    password: string;
    confirm_password: string;
}

export type AuthDataType = {
    user: User | null;
}`);

        fs.ensureFileSync('./prisma/schema.prisma');
        fs.appendFileSync('./prisma/schema.prisma', `\nenum UserRole {
  USER
  ADMIN
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String?
  password  String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  roles     Role[]
}

model Role {
  id    Int      @id @default(autoincrement())
  name  UserRole
  users User[]
}`);
    });

program.parse();

// execute command "npx prisma generate"
exec('npx prisma generate', (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        return;
    }

    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
    }

    console.log(`stdout: ${stdout}`);
});