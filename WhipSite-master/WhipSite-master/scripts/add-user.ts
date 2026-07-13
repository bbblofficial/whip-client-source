import { PrismaClient } from '@prisma/client'
const bcrypt = require('bcrypt')

const prisma = new PrismaClient()

async function main() {
    const username = process.argv[2]
    const password = process.argv[3]

    if (!username || !password) {
        console.error('Usage: npx ts-node scripts/add-user.ts <username> <password>')
        process.exit(1)
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = await prisma.user.upsert({
        where: { username },
        update: { password_hash: hashedPassword },
        create: {
            username,
            password_hash: hashedPassword,
        },
    })
    console.log('User created/updated:', user.username)
}

main()
    .catch((e) => {
        console.error(e)
        process.exit(1)
    })
    .finally(async () => {
        await prisma.$disconnect()
    })
