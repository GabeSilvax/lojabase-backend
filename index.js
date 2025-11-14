const express = require('express');
const { PrismaClient } = require('@prisma/client');

require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

const cors = require('cors');

const app = express();
const prisma = new PrismaClient();
const PORT = 3000; 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');



app.use(express.json());
app.use (cors());
// Autenticação com Middleware com token
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Acesso negado, Token não fornecido.'});
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (erro) {
        return res.status(403).json({ erro: 'Token invalido ou expirado.'});
    }
}

app.get('/', (req, res) => {
    res.send('API da LojaBase rodando');
});

app.get('/produtos', verificarToken, async (req, res) => {
    try {
        const produtos = await prisma.produto.findMany();
        res.json(produtos);
    }   catch (error) {
        console.error('Erro ao Buscar Produtos:', error); 
        res.status(500).json({ erro: 'Erro ao buscar produtos'});
    }
});

app.post('/produtos', verificarToken, async (req, res) => {
    try {
        const { nome, descricao, preco } = req.body;

        if (!nome || !descricao || !preco) {
            return res.status(400).json({ error: 'Todos os campos são obrigatorios.'});
        }

        const novoProduto = await prisma.produto.create({
            data: {nome, descricao, preco },
        });

        res.status(201).json(novoProduto);
    }   catch (error) {
        console.error('Erro ao criar produto:', error);
        res.status(500).json({ error: 'Erro ao criar produto' });
    }
});

app.put('/produtos/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nome, descricao, preco } = req.body;

        const produtoExistente = await prisma.produto.findUnique({
            where: { id: Number(id) }, 
        });

        if (!produtoExistente) {
           return res.status(404).json({ erro: 'Produto não encontrado.' });     
        }

        const produtoAtualizado = await prisma.produto.update({
            where: { id: Number(id) },
            data: { nome, descricao, preco },
        });

        res.json(produtoAtualizado);
    }   catch (error) {
        console.error('Erro ao atualizar produto', error);
        res.status(500).json({ erro: 'Erro ao atualizar o produto.'});
    }
});

app.delete('/produtos/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const produtoExistente = await prisma.produto.findUnique({
            where: { id: Number(id) },
        });

        if (!produtoExistente) {
            return res.status(404).json ({ erro: 'Produto não encontrado.' });
        }

        await prisma.produto.delete({
            where: { id:Number(id) },
        });

        res.json({ mensagem: 'Produto excluido com sucesso.' });
    }   catch (error) {
        console.error('Erro ao deletar o produto:', error);
        res.status(500).json({ erro: 'Erro ao deletar o produto.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});

// Autenticação de Login

app.post('/clientes', async (req, res) => {
    try{
        const {nome, email, senha} = req.body;

        if (!nome || !email || !senha) {
            return res.status(400).json({ erro: 'Preencha todos os campos.' });
        }

        const existente = await prisma.cliente.findUnique({ where: { email } });
        if (existente) {
            return res.status(400).json({ erro: 'Email ja cadastrado.'});
        }
    

    const senhaHash = await bcrypt.hash(senha, 10);

    const novoCliente = await prisma.cliente.create({
        data: { nome, email, senha: senhaHash },
    });

    res.status(201).json({ mensagem: 'Cliente cadastrado com sucesso.' });
    } catch (error) {
        console.error('Erro ao cadastrar o cliente:', error);
        res.status(500).json({ erro: 'Erro ao cadastrar cliente.'});
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, senha } = req.body

        if (!email || !senha) {
            return res.status(400).json({ erro: 'Informe o email e senha.' });
        }

        const cliente = await prisma.cliente.findUnique ({ where: {email} });
        if (!cliente) {
            return res.status(401).json({ erro: 'Email ou senha inválidos.' });
        }

        const senhaValida = await bcrypt.compare(senha, cliente.senha);
        if (!senhaValida) {
            return res.status(401).json({ erro: 'Email ou senha inválidos.' });
        }

        const token = jwt.sign(
            { id: cliente.id, email: cliente.email }, 
            JWT_SECRET, 
            {expiresIn: '2h',}
        );

        res.json({ mensagem: 'Login bem-sucedido!', token });
        } catch (error) {
            console.error('Erro ao cadastrar o cliente:', error);
            res.status(500).json({ erro: 'Erro ao cadastrar o cliente.' });
        }
});

app.get('/clientes', verificarToken, async (req, res) => {
    try {
        const clientes = await prisma.cliente.findMany({
            select: { id: true, nome: true, email: true, criadoEm: true },
        });
        res.json(clientes);
    }   catch (error) {
        console.error('Erro ao buscar os clientes:', error);
        res.status(500).json({ erro: 'Erro ao buscar clientes.'});
    }
})

app.put('/clientes/:id', verificarToken, async (req, res) => {
    try{
        const { id } = req.params;
        const { nome, email, senha } = req.body;

        const clienteExistente = await prisma.cliente.findUnique({
            where : { id: Number(id) },
        });

        if (!clienteExistente) {
            return res.status(404).json({ erro: 'Cliente nao encontrado.' });
        }

        let senhaHash = clienteExistente.senha;
        if (senha) {
            senhaHash = await bcrypt.hash(senha, 10);
        }

        const clienteAtualizado = await prisma.cliente.update({
            where : { id: Number(id) },
            data: { nome, email, senha: senhaHash },
        });

        res.json({ mensagem: 'Cliente atualizado com sucesso!', clienteAtualizado});
    }   catch (error) {
        console.error('Erro ao atualizar o cliente:', error);
        res.status(500).json({ erro: 'Erro ao atualizar o cliente'});
    }
});

app.delete('/clientes/:id', verificarToken, async (req, res) => {
    try { 
        const { id } = req.params;

        const clienteExistente = await prisma.cliente.findUnique({
            where : { id: Number(id) },
        });

        if (!clienteExistente) {
            return res.status(404).json({ erro: 'Cliente não encontrado.'});
        }

        await prisma.cliente.delete({
            where: { id: Number(id) },
        });

        res.json({ mensagem: 'Cliente excluido com sucesso.'});
    }   catch (error) {
        console.error('Erro ao excluir o cliente:', error);
        res.status(500).json({ erro: 'Erro ao excluir o cliente.'});
    }
});