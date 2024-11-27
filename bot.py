from logging import info
from os import link
from urllib import request, parse
from discord.embeds import EmptyEmbed
import logging
import discord
import json
import re
import datetime
import base64
import sqlite3
import time
import os


def Find(string): 
  
    #Defining/finding the link
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 

    #Google API that ended up not being very useful
'''def check_url_google(url,message,show_ok):
    os.environ
    url = parse.quote(url)
    req =  request.Request("https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE"\
        f"&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key={os.environ["API_KEY_GOOGLE"]}&uri={url}")
    resp = request.urlopen(req).read()
    resp_json = json.loads(resp)
    
    mention = message.author.mention
    answer = None

    if resp.get("threat"):
        threatTypes = resp_json.get("threat").get("threatTypes")
        if "MALWARE" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains malware and was deleted."
        elif "SOCIAL_ENGINEERING" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains phishing and was deleted."
        elif "UNWANTED_SOFTWARE" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains unwanted software and was deleted."
        elif "THREAT_TYPE_UNSPECIFIED" in threatTypes:
            message.delete()
            answer= f"{mention} Your link is an unspecified threat type."
        else: 
            answer = f"{mention} Your link is an unknown threat."
    elif show_ok:
        answer = f"{mention} Your link is OK."
    #return answer'''
    
    
def check_url_virustotal(url,message,show_ok):
    #The Discord user
    mention = message.author.mention
    answer = None
    ok = True
    #Setting up the database so I don't have to use the API for links/websites I have already scanned
    database = sqlite3.connect("C:\\Users\\Andrew\\Documents\\CodingProjects\\Discord Bot\\links.db")
    cursor = database.cursor()
    try:
        cursor.execute("CREATE TABLE links(Link TEXT, Status TEXT)")
    except:
        pass
    cursor.execute(f'SELECT Status FROM links WHERE Link = "{url}"')
    result = cursor.fetchone()
    status = result[0] if result else None
    print(status)
    #If the link/website is not in the database (hasn't been scanned before), we call the API
    if not status:
        for x in range(0,3):
            api_key = os.environ["API_KEY_VIRUSTOTAL"]
            print(url)
            params = parse.urlencode({'apikey': api_key, 'url':url}).encode("utf-8")
            req =  request.Request(f"https://www.virustotal.com/vtapi/v2/url/scan",
                    data=params)
            resp = request.urlopen(req).read()
            print(resp)
            resp_json = json.loads(resp)
            resource = resp_json.get("scan_id")
            req =  request.Request(f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={resource}")
            resp = request.urlopen(req).read()
            print(resp)
            resp_json = json.loads(resp)
            if 'positives' in resp_json:
                break
            time.sleep(1)
        if 'positives' not in resp_json:
            answer = "Couldn't scan the link"
        elif resp_json.get("positives") >= 1:#At least one vendor saw this url as malicious
            answer = f"{mention} Your link is malicious and was deleted."
            ok = False
            #Inserting the resulting "Not Malicious" or "Malicious" into the database
            cursor.execute(f"INSERT INTO links VALUES ('{url}','Malicious')")
            database.commit()
            database.close()
        else:
            if show_ok:
                answer = f"{mention} Your link is OK."
            cursor.execute(f"INSERT INTO links VALUES ('{url}','Not Malicious')")
            database.commit()
            database.close()
    else:
        #If the link is Malicous, the message is deleted and the user that posted the message is notified
        if status == "Malicious":
            answer = f"{mention} Your link is malicious and was deleted."
            ok = False
        elif show_ok:
            answer = f"{mention} Your link is OK."
    return answer,ok


client = discord.Client(case_insensitive = True)
logging_channel = {}
virus_check = {}

@client.event
async def on_ready():
    print('Logged in as {0.user}'.format(client))

@client.event
async def on_message(message):
    global logging_channel
    global virus_check
    if message.author == client.user:
        return

    #Commands that the users/admins use in Discord
    #The help command, sends a message of all of the commands the bot has and a description of each
    if message.content.startswith('v/help'):
        embedVar = discord.Embed(colour=0x00ff00,description="`v/c [link]`\n Checks a link\n `v/log [channel]/off`\n Selects the channel to log messages deleted by virus check\n `v/viruscheck on/off`\n Enables automatically checking messages for viruses, this is logged in the `v/log` channel", inline=False)
        await message.channel.send(embed=embedVar)

        discord.Embed(colour=0x00ff00,description=f"__**VIEW AT YOUR OWN RISK**__\n|| {message.content}|| ")
    
    #The check command, if the user wants to manually check if a link is malicious or not they can use this command
    elif message.content.startswith('v/c '):
        url = message.content.split()[1]
        answer,ok = check_url_virustotal(url,message,show_ok=True)
        if not ok:
            await message.delete()
        await message.channel.send('{0}'.format(answer))
    
    #The log command, this is an administrator exclusive command
    elif message.content.startswith('v/log '):
        channel_name = message.content.split()[1]
        #If they want to disable this command they can
        if channel_name == "off" and message.author.guild_permissions.administrator:
            logging_channel[message.guild.id] = None
            await message.channel.send("Logging disabled")
        else:
            #Defining the channel that the logging messages will be sent to. (message.author.id == 301022269709221898 is me in case I want to test the command)
            if channel_name.startswith("<#") and message.author.guild_permissions.administrator or message.author.id == 301022269709221898:
                channel_name = channel_name[2:-1]
                logging_channel[message.guild.id] = client.get_channel(int(channel_name))
            else:
                logging_channel[message.guild.id] = discord.utils.get(client.get_all_channels(), name=channel_name)
            channel = logging_channel[message.guild.id].mention
            await message.channel.send(f"Logging in {channel} is now enabled")
        if message.author.guild_permissions.administrator == False:
            if message.author.id == 301022269709221898:
                return
            else:
                await message.channel.send('You do not have the required permissions to use this command (Administrator)')

    #The viruscheck command, this is also an administrator exclusive command
    elif message.content.startswith('v/viruscheck '):
        #If they want to disable this command they can
        if message.content.split()[1] == "off":
            virus_check[message.guild.id] = None
            await message.channel.send('Virus checking disabled')
        else:
            #Enabling the API and database system to work
            if message.content.split()[1] == "on" and (message.author.guild_permissions.administrator or message.author.id == 301022269709221898):
                if virus_check.get(message.guild.id):
                    await message.channel.send('Virus checking is already enabled')
                else:
                    virus_check[message.guild.id] = True
                    await message.channel.send('Virus checking enabled')
        if message.author.guild_permissions.administrator == False:
            if message.author.id == 301022269709221898:
                return
            else:
                await message.channel.send('You do not have the required permissions to use this command (Administrator)')
                
    elif virus_check.get(message.guild.id):
        urls = Find(message.content)
        for url in urls:
            answer,ok = check_url_virustotal(url,message,show_ok=False)
            if answer:

                try:
                    await message.delete()
                except:
                    print(f"Might not have deleted message in {message.guild.name} :)")
                bot_message =  await message.channel.send('{1}'.format(url,answer,))
                await bot_message.delete(delay=5)
                
                #Formatting the logging channel
                if logging_channel.get(message.guild.id): 
                    #The time of when the message was sent
                    time = datetime.datetime.now().strftime('%H:%M:%S')
                    #This embed is to hide the link that was sent with a spoiler so no one clicks on it
                    deletedmsg = discord.Embed(colour=0x00ff00,description=f"__**VIEW AT YOUR OWN RISK**__\n|| {message.content}|| ")
                    await logging_channel[message.guild.id].send(f"`[{time}]`**{message.author}**'s link has been detected as unsafe and was deleted from {message.channel.mention}:", embed=deletedmsg)
            if len(urls)> 1:
                time.sleep(15)
                    



discord_token = os.environ["DISCORD_TOKEN"]
client.run(discord_token)