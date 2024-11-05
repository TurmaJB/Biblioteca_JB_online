const express = require('express')
const Sequelize = require('sequelize')
const dotenv = require('dotenv')
const cors = require('cors')
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const bcrypt = require('bcrypt') 

dotenv.config()

const app = express()
app.use(express.json())
app.use(cors())

app.use('/img/capas-livro', express.static(path.join(__dirname, 'img/capas-livro')))

const uploadDir = path.join(__dirname, 'img/capas-livro')
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true })
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'img/capas-livro');
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname)
        cb(null, `${Date.now()}${ext}`)
    }
})
const upload = multer({ storage })

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASS, {
    host: process.env.DB_HOST,
    dialect: 'mysql'
})

const Usuario = sequelize.define('Usuario', {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    nome: {
        type: Sequelize.STRING,
        allowNull: false
    },
    email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
    },
    senha: {
        type: Sequelize.STRING,
        allowNull: false
    },
    masp: {  
        type: Sequelize.STRING,
        allowNull: true, 
        unique: true
    }
}, {
    timestamps: true,
    tableName: 'usuarios' 
});


const Livro = sequelize.define('Livro', {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    titulo: {
        type: Sequelize.STRING,
        allowNull: false
    },
    autor: {
        type: Sequelize.STRING,
        allowNull: false
    },
    quantidade: {
        type: Sequelize.INTEGER,
        allowNull: false
    },
    editora: {
        type: Sequelize.STRING,
        allowNull: false
    },
    assunto: {
        type: Sequelize.STRING
    },
    faixaEtaria: {
        type: Sequelize.ENUM('Livre', 'Infantil', 'Infantojuvenil', 'Adulto'),
        allowNull: false
    },
    imagem: {
        type: Sequelize.STRING,
        allowNull: true
    }
}, {
    timestamps: true,
    tableName: 'livros' 
})

const Emprestimo = sequelize.define('Emprestimo', {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    data_vencimento: { 
        type: Sequelize.DATE,
        allowNull: false
    },
    renovacoes: { 
        type: Sequelize.INTEGER,
        defaultValue: 0
    },
    usuarioId: { 
        type: Sequelize.INTEGER,
        references: {
            model: 'usuarios',
            key: 'id'
        }
    },
    livroId: { 
        type: Sequelize.INTEGER,
        references: {
            model: 'livros',
            key: 'id'
        }
    }
}, {
    timestamps: true,
    tableName: 'emprestimos' 
})

Usuario.hasMany(Emprestimo, { foreignKey: 'usuarioId' })
Livro.hasMany(Emprestimo, { foreignKey: 'livroId' })
Emprestimo.belongsTo(Usuario, { foreignKey: 'usuarioId' })
Emprestimo.belongsTo(Livro, { foreignKey: 'livroId' })

sequelize.sync({ alter: true }).then(() => {
    console.log('Banco de dados e tabelas sincronizados!')
}).catch((error) => {
    console.error('Erro ao sincronizar banco de dados:', error)
})

// Rota para registrar o usuário (com bcrypt para hashear a senha)
app.post('/registrar', async (req, res) => {
    try {
        const { nome, email, senha } = req.body;

        // Hashear a senha usando bcrypt
        const saltRounds = 10;
        const senhaHasheada = await bcrypt.hash(senha, saltRounds);

        // Criar o usuário com a senha hasheada
        const usuario = await Usuario.create({
            nome,
            email,
            senha: senhaHasheada // Salvar a senha hasheada no banco de dados
        });

        res.status(201).json(usuario);
    } catch (error) {
        res.status(400).json({ erro: error.message });
    }
})


app.post('/registrar-bibliotecario', async (req, res) => {
    try {
        const { nome, email, senha, masp } = req.body;

        // Hashear a senha usando bcrypt
        const saltRounds = 10;
        const senhaHasheada = await bcrypt.hash(senha, saltRounds);

        // Criar o bibliotecário com a senha hasheada e masp
        const bibliotecario = await Usuario.create({
            nome,
            email,
            senha: senhaHasheada,
            masp  // Armazenar o MASP
        });

        res.status(201).json(bibliotecario);
    } catch (error) {
        res.status(400).json({ erro: error.message });
    }
});

app.post('/login-bibliotecario', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const bibliotecario = await Usuario.findOne({ where: { email, masp: { [Sequelize.Op.not]: null } } });

        if (!bibliotecario) {
            return res.status(401).json({ erro: 'Credenciais inválidas ou não é bibliotecário.' });
        }

        // Comparar a senha fornecida com o hash armazenado
        const senhaValida = await bcrypt.compare(senha, bibliotecario.senha);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }

        // Retornar as informações do bibliotecário sem a senha
        res.status(200).json({
            id: bibliotecario.id,
            nome: bibliotecario.nome,
            email: bibliotecario.email,
            masp: bibliotecario.masp
        });
    } catch (error) {
        res.status(500).json({ erro: 'Erro no servidor: ' + error.message });
    }
});



// Rota para login (com bcrypt para verificar a senha hasheada)
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const usuario = await Usuario.findOne({ where: { email } });

        if (!usuario) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }

        // Comparar a senha fornecida com o hash armazenado
        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }

        // Retornar as informações do usuário sem a senha
        res.status(200).json({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email
        });
    } catch (error) {
        res.status(500).json({ erro: 'Erro no servidor: ' + error.message });
    }
})

// Rota para adicionar livros
app.post('/livros', upload.single('imagem'), async (req, res) => {
    try {
        const { titulo, autor, quantidade, editora, assunto, faixaEtaria } = req.body
        const imagem = req.file ? req.file.filename : null;

        const livro = await Livro.create({
            titulo,
            autor,
            quantidade,
            editora,
            assunto,
            faixaEtaria,
            imagem
        })

        res.status(201).json(livro)
    } catch (error) {
        console.error('Erro ao adicionar livro:', error)
        res.status(500).json({ erro: 'Erro no servidor: ' + error.message })
    }
})

// Rota para atualizar um livro
app.put('/livros/:id', upload.single('imagem'), async (req, res) => {
    try {
        const livroId = req.params.id;
        const { titulo, autor, quantidade, editora, assunto, faixaEtaria } = req.body
        const livro = await Livro.findByPk(livroId);

        if (!livro) {
            return res.status(404).json({ erro: 'Livro não encontrado' })
        }

        livro.titulo = titulo || livro.titulo
        livro.autor = autor || livro.autor
        livro.quantidade = quantidade || livro.quantidade
        livro.editora = editora || livro.editora
        livro.assunto = assunto || livro.assunto
        livro.faixaEtaria = faixaEtaria || livro.faixaEtaria

        if (req.file) {
            livro.imagem = req.file.filename
        }

        await livro.save()
        res.status(200).json(livro)
    } catch (error) {
        console.error('Erro ao atualizar livro:', error)
        res.status(500).json({ erro: 'Erro no servidor: ' + error.message })
    }
})

// Rota para listar todos os livros
app.get('/livros', async (req, res) => {
    try {
        const livros = await Livro.findAll()
        res.status(200).json(livros)
    } catch (error) {
        res.status(400).json({ erro: error.message })
    }
})

// Rota para listar todos os livros alugados
app.get('/livros-alugados', async (req, res) => {
    try {
        const emprestimos = await Emprestimo.findAll({
            include: [Usuario, Livro]
        });
        res.status(200).json(emprestimos);
    } catch (error) {
        res.status(400).json({ erro: error.message })
    }
})

// Rota para alugar um livro
app.post('/alugar', async (req, res) => {
    try {
        const { usuarioId, livroId } = req.body;

        if (!usuarioId || !livroId) {
            return res.status(400).json({ erro: 'Parâmetros faltando: usuário ou livro não informados.' })
        }

        const usuario = await Usuario.findByPk(usuarioId)
        const livro = await Livro.findByPk(livroId)

        if (usuario && livro && livro.quantidade > 0) {
            const data_vencimento = new Date()
            data_vencimento.setDate(data_vencimento.getDate() + 7)

            const emprestimo = await Emprestimo.create({
                usuarioId,
                livroId,
                data_vencimento
            })

            livro.quantidade -= 1
            await livro.save()

            res.status(201).json(emprestimo)
        } else {
            res.status(400).json({ erro: 'Usuário ou livro inválido, ou livro não disponível' })
        }
    } catch (error) {
        console.error('Erro ao alugar livro:', error);
        res.status(500).json({ erro: 'Erro no servidor: ' + error.message })
    }
})

// Rota para devolver um livro
app.delete('/devolver/:emprestimoId', async (req, res) => {
    try {
        const { emprestimoId } = req.params;
        const emprestimo = await Emprestimo.findByPk(emprestimoId)

        if (emprestimo) {
            const livro = await Livro.findByPk(emprestimo.livroId)

            if (livro) {
                livro.quantidade += 1;
                await livro.save()
                await emprestimo.destroy()
                res.status(200).json({ mensagem: 'Livro devolvido com sucesso' })
            } else {
                res.status(400).json({ erro: 'Livro não encontrado' })
                
            }
        } else {
            res.status(400).json({ erro: 'ID de empréstimo inválido' })
        }
    } catch (error) {
        res.status(400).json({ erro: error.message })
    }
})

// Rota para renovar um livro
app.post('/renovar', async (req, res) => {
    try {
        const { emprestimoId } = req.body

        const emprestimo = await Emprestimo.findByPk(emprestimoId)

        if (emprestimo && emprestimo.renovacoes < 2) {
            emprestimo.renovacoes += 1
            emprestimo.data_vencimento.setDate(emprestimo.data_vencimento.getDate() + 7)
            await emprestimo.save()

            res.status(200).json({ mensagem: 'Livro renovado com sucesso!' })
        } else {
            res.status(400).json({ erro: 'Não é possível renovar mais vezes' })
        }
    } catch (error) {
        res.status(400).json({ erro: error.message })
    }
})

// Rota para listar os empréstimos de um usuário
app.get('/usuario/:usuarioId/emprestimos', async (req, res) => {
    try {
        const { usuarioId } = req.params;
        const emprestimos = await Emprestimo.findAll({
            where: { usuarioId },
            include: [Livro]
        })
        res.status(200).json(emprestimos)
    } catch (error) {
        res.status(400).json({ erro: error.message })
    }
})

const PORT = process.env.PORT || 3750
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`)
})
