import { Command } from 'commander'
import { version } from '../package.json'
import prompt from 'prompt-sync'
import colors from 'colors'
import fs from 'fs-extra'

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
        fs.ensureFileSync('./src/components/layouts/auth/guest-layout.tsx');
        fs.ensureFileSync('./src/components/layouts/auth/universal-layout.tsx');
        fs.ensureFileSync('./src/components/providers/auth/auth-provider.tsx');
        fs.ensureFileSync('./src/context/auth/auth-context.ts');
        fs.ensureFileSync('./src/lib/auth/auth.ts');
        fs.ensureFileSync('./src/lib/auth/prisma.ts');
        fs.ensureFileSync('./src/lib/auth/user.ts');
        fs.ensureFileSync('./src/types/auth/auth.ts');
    });

program.parse();