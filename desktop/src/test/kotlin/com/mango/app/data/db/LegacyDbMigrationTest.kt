package com.mango.app.data.db

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.io.File
import java.sql.DriverManager

/**
 * 品牌重写（YunX → MangoRouter）数据迁移回归：老用户「零手动操作」升级不丢数据的契约。
 *
 * 三层迁移（云析时期 → mango 时期）：
 * 1. 库文件改名 yunx.db(-wal/-shm) → mango-router.db(-wal/-shm)：[AppDatabase.open] 首次打开时；
 * 2. 旧库里的数据原样可读（改名不是重建，schema/内容都不动）；
 * 3. 新名库已存在时绝不覆盖（幂等：二次打开不再动任何文件）。
 *
 * 目录层与 prefs 层迁移在 AppContext（单例 + java.util.prefs，测试进程内不可隔离），不在此覆盖。
 */
class LegacyDbMigrationTest {

    private fun newDir(): File = Files.createTempDirectory("mango-mig-test").toFile()

    /** 用旧名直接建一个「云析时期」的库，写入一行可识别数据 */
    private fun seedLegacyDb(dir: File): String {
        DriverManager.getConnection("jdbc:sqlite:${File(dir, "yunx.db").absolutePath}").use { c ->
            c.createStatement().use { st ->
                st.execute("PRAGMA journal_mode=WAL")
                st.execute("CREATE TABLE legacy_marker(t TEXT)")
                st.execute("INSERT INTO legacy_marker VALUES ('old-data')")
            }
        }
        // WAL 模式下数据可能还在 -wal 里，模拟「强杀后未 checkpoint」的真实老用户状态
        return "old-data"
    }

    private fun rawQuery(dir: File, db: String, sql: String): String? =
        DriverManager.getConnection("jdbc:sqlite:${File(dir, db).absolutePath}").use { c ->
            c.createStatement().use { st -> st.executeQuery(sql).use { rs -> if (rs.next()) rs.getString(1) else null } }
        }

    @Test
    fun `legacy yunx db renames to mango-router db with wal and shm`() {
        val dir = newDir()
        seedLegacyDb(dir)
        // 强杀现场：主库 + 未合并的 WAL + shm 索引
        File(dir, "yunx.db-wal").writeText("")
        File(dir, "yunx.db-shm").writeText("")

        AppDatabase.open(dir)

        assertTrue("主库应已改名为新代文件名", File(dir, "mango-router.db").isFile)
        assertTrue("未 checkpoint 的 WAL 必须跟着改名，否则数据全在 -wal 里等于清库", File(dir, "mango-router.db-wal").isFile)
        assertTrue(File(dir, "mango-router.db-shm").isFile)
        assertFalse("旧主库应已消失（是改名不是复制，不占双份空间）", File(dir, "yunx.db").isFile)
        assertFalse(File(dir, "yunx.db-wal").isFile)
    }

    @Test
    fun `legacy data survives rename and stays readable`() {
        val dir = newDir()
        seedLegacyDb(dir)

        AppDatabase.open(dir)

        // 改名不是重建：旧库自定义表内容原样保留
        assertEquals("old-data", rawQuery(dir, "mango-router.db", "SELECT t FROM legacy_marker"))
    }

    @Test
    fun `migration is idempotent - existing new db is never touched`() {
        val dir = newDir()
        seedLegacyDb(dir)
        AppDatabase.open(dir)
        val firstOpen = File(dir, "mango-router.db").lastModified()

        // 二次打开（模拟日常启动）：迁移必须幂等，绝不把新库顶掉
        AppDatabase.open(dir)

        assertEquals("新名库已存在时迁移不得再动文件", firstOpen, File(dir, "mango-router.db").lastModified())
        assertEquals("old-data", rawQuery(dir, "mango-router.db", "SELECT t FROM legacy_marker"))
        assertFalse(File(dir, "yunx.db").isFile)
    }

    @Test
    fun `fresh install without legacy db creates new db directly`() {
        val dir = newDir()
        AppDatabase.open(dir)
        assertTrue(File(dir, "mango-router.db").isFile)
        assertFalse("全新安装不应生成任何旧名文件", File(dir, "yunx.db").isFile)
    }
}
