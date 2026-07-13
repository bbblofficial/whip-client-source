const { PrismaClient } = require('@prisma/client')
const bcrypt = require('bcrypt')

const prisma = new PrismaClient()

async function main() {
    const hashedPassword = await bcrypt.hash('123', 12)
    const user = await prisma.user.upsert({
        where: { username: '123' },
        update: { password_hash: hashedPassword },
        create: {
            username: '123',
            password_hash: hashedPassword,
        },
    })
    console.log('User 123 created/updated:', user.username)
}

main()
    .catch((e) => {
        console.error(e)
        process.exit(1)
    })
    .finally(async () => {
        await prisma.$disconnect()
    })
