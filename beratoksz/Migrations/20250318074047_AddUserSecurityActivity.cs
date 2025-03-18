using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace beratoksz.Migrations
{
    /// <inheritdoc />
    public partial class AddUserSecurityActivity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsActiveSession",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionEnd",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionStart",
                table: "ActivityLogs");

            migrationBuilder.CreateTable(
                name: "UserSecurityActivities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ActivityType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IPAddress = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserAgent = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsSuccess = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserSecurityActivities", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserSecurityActivities");

            migrationBuilder.AddColumn<bool>(
                name: "IsActiveSession",
                table: "ActivityLogs",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "SessionEnd",
                table: "ActivityLogs",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SessionId",
                table: "ActivityLogs",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTime>(
                name: "SessionStart",
                table: "ActivityLogs",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }
    }
}
