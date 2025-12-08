import discord, json, datetime, string, random, asyncio, os, pytz
from discord.ext import commands, tasks
from discord.commands import slash_command,Option
from datetime import datetime, timedelta

bot = commands.Bot(intents=discord.Intents.all(), help_command=None, command_prefix="!")



@bot.event
async def on_ready():
    bot.add_view(CloseTicketView())
    bot.add_view(TicketView())
    countdown_task.start()


class embed_modal(discord.ui.Modal):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.add_item(discord.ui.InputText(label="Title",placeholder="請輸入嵌入訊息標題"))
        self.add_item(discord.ui.InputText(label="Description",placeholder="請輸入嵌入訊息內文",style=discord.InputTextStyle.long))
        
    async def callback(self, interaction):
        title = self.children[0].value
        description = self.children[1].value

        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Colour.random()
        )
        await interaction.channel.send(embed=embed)
        await interaction.response.send_message("發送成功", ephemeral=True)


@bot.slash_command(description="發送嵌入消息")
async def embed(ctx):
    if not ctx.author.guild_permissions.administrator:
        return await ctx.respond("您需要擁有**管理者(Administrator)**權限，才可以進行此項操作", ephemeral=True)
    modal = embed_modal(title="發送遷入訊息")
    await ctx.send_modal(modal)
    
@bot.slash_command(name="add_reaction_role", description="設定反應對應身分組")
async def add_reaction_role(ctx,
                            message_id: Option(str, "反應訊息 ID"),
                            emoji: Option(str, "emoji"),
                            role: Option(discord.Role, "身分組")):
    if not ctx.author.guild_permissions.administrator:
        return await ctx.respond("您需要擁有**管理者(Administrator)**權限，才可以進行此項操作", ephemeral=True)
    with open("role.json", "r") as f:
        data = json.load(f)
    data["reaction_roles"].append({
        "message_id": message_id,
        "emoji": emoji,
        "role_id": role.id
    })
    with open("role.json", "w") as f:
        json.dump(data, f, indent=4)
    channel = ctx.channel
    try:
        message = await channel.fetch_message(int(message_id))
        await message.add_reaction(emoji)
        embed = discord.Embed(title="反應身分 設置完成",description=f"訊息ID: `{message_id}`\nEmoji: {emoji}\nRole: {role.mention}",color=discord.Colour.random())
        await ctx.respond(embed=embed, ephemeral=True)
    except Exception as e:
        await ctx.respond(f"無法在該訊息上加反應：{e}", ephemeral=True)

@bot.event
async def on_raw_reaction_add(payload):
    if payload.member.bot:
        return
    with open("role.json", "r") as f:
        data = json.load(f)
    for entry in data["reaction_roles"]:
        if str(payload.message_id) == entry["message_id"] and str(payload.emoji) == entry["emoji"]:
            guild = bot.get_guild(payload.guild_id)
            role = guild.get_role(entry["role_id"])
            member = guild.get_member(payload.user_id)
            if role and member:
                await member.add_roles(role)
                try:
                    await member.send(f"新增 `{role.name}` 身分組")
                except:
                    pass

@bot.event
async def on_raw_reaction_remove(payload):
    with open("role.json", "r") as f:
        data = json.load(f)
    for entry in data["reaction_roles"]:
        if str(payload.message_id) == entry["message_id"] and str(payload.emoji) == entry["emoji"]:
            guild = bot.get_guild(payload.guild_id)
            role = guild.get_role(entry["role_id"])
            member = guild.get_member(payload.user_id)
            if role and member:
                await member.remove_roles(role)
                try:
                    await member.send(f"移除 `{role.name}` 身分組")
                except:
                    pass
                
@bot.slash_command(name="set_welcome_role", description="設定新成員加入時自動給予的身分組")
async def set_welcome_role(ctx, 
    role: Option(discord.Role, "選擇歡迎身分組"),
    target: Option(str, "選擇適用對象", choices=["人類", "機器人", "都給"])):
    
    if not ctx.author.guild_permissions.administrator:
        return await ctx.respond("您需要擁有**管理者(Administrator)**權限，才可以進行此項操作", ephemeral=True)
    with open("role.json", "r") as f:
        data = json.load(f)
    
    if "welcome_roles" not in data:
        data["welcome_roles"] = {}
    data["welcome_roles"][target] = role.id
    with open("role.json", "w") as f:
        json.dump(data, f, indent=4)
    embed = discord.Embed(title="設定完成",description=f"加入身分組：`{role.mention}`\n適用對象：`{target}`",color=discord.Colour.random())
    await ctx.respond(embed=embed, ephemeral=True)
    
@bot.event
async def on_member_join(member):
    with open("data.json","r") as file:
        wata = json.load(file)
    cid = wata["welcome"]
    ch = bot.get_channel(cid)
    await ch.send(f"歡迎 {member.mention}加入{member.guild.name}")
    with open("role.json", "r") as f:
        data = json.load(f)  
    welcome_roles = data.get("welcome_roles", {})
    if "人類" in welcome_roles and not member.bot:
        role = member.guild.get_role(welcome_roles["人類"])
        if role:
            await member.add_roles(role)
    
    if "機器人" in welcome_roles and member.bot:
        role = member.guild.get_role(welcome_roles["機器人"])
        if role:
            await member.add_roles(role)
    
    if "都給" in welcome_roles:
        role = member.guild.get_role(welcome_roles["都給"])
        if role:
            await member.add_roles(role)
            
@bot.slash_command(description="設置歡迎系統")
async def welcome_msg(ctx,
        channel:Option(discord.TextChannel,"訊息發送頻道")):
    
    with open("data.json","r") as file:
        data = json.load(file)
    
    data["welcome"] = channel.id
    with open("data.json", "w") as file:
        json.dump(data,file)
    await ctx.respond("設置成功", ephemeral=True)
    
class TicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="創建1v1頻道", style=discord.ButtonStyle.green, custom_id="create_ticket")
    async def create_ticket(self, button, interaction):
        user = interaction.user
        category = interaction.channel.category
        overwrites = {
            interaction.guild.default_role: discord.PermissionOverwrite(view_channel=False),
            user: discord.PermissionOverwrite(view_channel=True, send_messages=True, attach_files=True, embed_links=True)}
        channel = await category.create_text_channel(name=f"ticket-{user.name}", overwrites=overwrites)
        await channel.send(f"{user.mention} 嗨嗨！\n你今天過得如何？我們來聊天吧", view=CloseTicketView())
        await interaction.response.send_message(f"客服單已建立 －－> {channel.mention}。", ephemeral=True)

class CloseTicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="關閉工單", style=discord.ButtonStyle.red, custom_id="close_ticket")
    async def close_ticket(self, button, interaction):
        channel = interaction.channel
        messages = []
        taiwan_tz = pytz.timezone("Asia/Taipei")
        async for message in channel.history(limit=None):
            timestamp = message.created_at.replace(tzinfo=pytz.utc).astimezone(taiwan_tz)
            log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {message.author}: {message.content}"
            if message.attachments:
                for attachment in message.attachments:
                    log_entry += f"\n(附件: {attachment.url})"
            if message.embeds:
                for embed in message.embeds:
                    log_entry += f"\n(Embed: {embed.title if embed.title else '無標題'}) {embed.description if embed.description else '無描述'}"
                    if embed.image:
                        log_entry += f"\n(Embed 圖片: {embed.image.url})"
                    if embed.thumbnail:
                        log_entry += f"\n(Embed 縮圖: {embed.thumbnail.url})"
            messages.append(log_entry)
        messages.reverse()
        filename = f"chat_log_{channel.id}.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(messages))
        with open("data.json", "r") as file:
            data = json.load(file)
        chidd = data["ticket"]
        ch = interaction.guild.get_channel(chidd)
        await ch.send(file=discord.File(filename))
        os.remove(filename)
        await interaction.response.send_message("工單即將關閉...", ephemeral=True)
        await interaction.channel.delete()
    
@bot.slash_command(description="發送客服單面板")
async def ticket(ctx,logchannel:Option(discord.TextChannel,"對話紀錄頻道")):
    if not ctx.author.guild_permissions.administrator:
        embed = discord.Embed(title="❌｜發生錯誤", description="錯誤內容:\n```您沒有權限使用此指令！```", color=discord.Color.red())
        await ctx.respond(embed=embed, ephemeral=True)
        return
    view = TicketView()
    embed = discord.Embed(title="找小編聊天",description="點擊下方按鈕來開啟跟小編聊天的1v1頻道")
    await ctx.send(embed=embed, view=view)
    with open("data.json","r") as file:
        data = json.load(file)
    data["ticket"] = logchannel.id
    with open("data.json","w") as file:
        json.dump(data,file)
        
        
CHANNEL_ID = 1363361970895589446 # 替換成你的頻道 ID
MESSAGE_ID = 1363365055466311682  # 替換成要編輯的訊息 ID
EXAM_DATE = datetime(2026, 5, 16)

@tasks.loop(hours=1)
async def countdown_task():
    await update_countdown()

async def update_countdown():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print("找不到頻道")
        return

    try:
        message = await channel.fetch_message(MESSAGE_ID)
    except discord.NotFound:
        print("訊息不存在，請確認 MESSAGE_ID 正確")
        return

    today = datetime.now()
    days_left = (EXAM_DATE - today).days

    embed = discord.Embed(
        title="📚 會考倒數計時",
        description=f"離會考還有 **{days_left} 天**！\n加油！💪",
        color=discord.Color.blue()
    )
    embed.set_footer(text=f"會考日期：{EXAM_DATE.strftime('%Y/%m/%d')}")
    embed.timestamp = datetime.now()

    await message.edit(embed=embed)
    new_name = f"距離會考還有：{days_left} 天"
    vcchannel = bot.get_channel(1363363236690268170)
    await vcchannel.edit(name=new_name)

# 如果你還沒建立訊息，可以用這指令手動發一次
@bot.command()
async def send_countdown(ctx):
    today = datetime.now()
    days_left = (EXAM_DATE - today).days
    embed = discord.Embed(
        title="📚 會考倒數計時",
        description=f"離會考還有 **{days_left} 天**！\n加油！💪",
        color=discord.Color.blue()
    )
    embed.set_footer(text=f"會考日期：{EXAM_DATE.strftime('%Y/%m/%d')}")
    embed.timestamp = datetime.now()

    message = await ctx.send(embed=embed)
    await ctx.send(f"✅ 倒數訊息已發送，請儲存這個 MESSAGE_ID: `{message.id}`")
        
bot.run("")
