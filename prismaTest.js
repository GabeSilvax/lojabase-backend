const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();


async function main() {
    const produtos = await prisma.produto.findMany();
    console.log(produtos);     
}

main()
    .then(() => prisma.$disconnect())
    .catch(e => {
        console.error(e);
        prisma.$disconnect();
    });